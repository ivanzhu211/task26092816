package checksum

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// genFile 生成指定大小的伪随机内容文件，返回其路径。
func genFile(t *testing.T, dir string, size int64, seed uint64) string {
	t.Helper()
	path := filepath.Join(dir, fmt.Sprintf("img-%d.bin", seed))
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b9))
	buf := make([]byte, 4<<20)
	for written := int64(0); written < size; {
		n := int64(len(buf))
		if size-written < n {
			n = size - written
		}
		for i := range buf {
			buf[i] = byte(r.Uint64())
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
	return path
}

// refSum 用标准库直接算一遍，作为参照值。
func refSum(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func openStore(t *testing.T, chunk int64) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := Open(dir, WithChunkSize(chunk))
	if err != nil {
		t.Fatal(err)
	}
	return st, dir
}

func TestRegisterAndQuery(t *testing.T) {
	st, _ := openStore(t, 4<<20)
	path := genFile(t, t.TempDir(), 50<<20, 1)
	want := refSum(t, path)

	sum, err := st.Register(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if sum != want {
		t.Fatalf("sum = %s, want %s", sum, want)
	}

	reg, ok := st.QueryRegistration(path)
	if !ok || reg.Stale || reg.Checksum != want {
		t.Fatalf("query = %+v ok=%v", reg, ok)
	}

	// 未变化再次登记：直接返回登记值，不重写登记文件。
	fi1, _ := os.Stat(st.regFile(path))
	sum2, err := st.Register(context.Background(), path)
	if err != nil || sum2 != want {
		t.Fatalf("re-register = %s, %v", sum2, err)
	}
	fi2, _ := os.Stat(st.regFile(path))
	if !fi1.ModTime().Equal(fi2.ModTime()) {
		t.Fatal("unchanged file should not rewrite registration")
	}

	// 进度查询：已登记为 100%。
	p, ok := st.RegisterProgress(path)
	if !ok || p.ProcessedBytes != p.TotalBytes || p.TotalBytes != 50<<20 {
		t.Fatalf("progress = %+v ok=%v", p, ok)
	}
}

func TestRegisterStaleAndRecompute(t *testing.T) {
	st, _ := openStore(t, 4<<20)
	dir := t.TempDir()
	path := genFile(t, dir, 20<<20, 2)
	old := refSum(t, path)
	if _, err := st.Register(context.Background(), path); err != nil {
		t.Fatal(err)
	}

	// 改写文件（大小也变化）：登记值应失效。
	time.Sleep(2 * time.Millisecond)
	path2 := genFile(t, dir, 21<<20, 3)
	if path != path2 {
		os.Remove(path)
		os.Rename(path2, path)
	}
	reg, ok := st.QueryRegistration(path)
	if !ok || !reg.Stale {
		t.Fatalf("expected stale, got %+v ok=%v", reg, ok)
	}
	if reg.Checksum != old {
		t.Fatal("stale query should still report the old registered value")
	}

	// 重新登记：覆盖为新值。
	want := refSum(t, path)
	sum, err := st.Register(context.Background(), path)
	if err != nil || sum != want {
		t.Fatalf("re-register = %s, %v want %s", sum, err, want)
	}
	if reg, _ := st.QueryRegistration(path); reg.Stale {
		t.Fatal("should not be stale after re-register")
	}
}

func TestVerifyBasic(t *testing.T) {
	st, dir := openStore(t, 4<<20)
	path := genFile(t, t.TempDir(), 30<<20, 4)
	sum := refSum(t, path)

	// 大写期望值应被接受并归一化。
	res, err := st.Verify(context.Background(), "job-1", path, strings.ToUpper(sum))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match || res.Actual != sum || res.Expected != sum {
		t.Fatalf("res = %+v", res)
	}
	// 重复发起：直接返回结论。
	res2, err := st.Verify(context.Background(), "job-1", path, sum)
	if err != nil || !res2.Match {
		t.Fatalf("res2 = %+v, %v", res2, err)
	}
	// 同一编号换期望值/路径：拒绝。
	if _, err := st.Verify(context.Background(), "job-1", path, strings.Repeat("0", 64)); !errors.Is(err, ErrCheckConflict) {
		t.Fatalf("expect conflict, got %v", err)
	}
	other := genFile(t, t.TempDir(), 1<<20, 5)
	if _, err := st.Verify(context.Background(), "job-1", other, sum); !errors.Is(err, ErrCheckConflict) {
		t.Fatalf("expect conflict, got %v", err)
	}
	// 格式不合法：直接拒绝。
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("0", 63)} {
		if _, err := st.Verify(context.Background(), "job-x", path, bad); !errors.Is(err, ErrInvalidChecksum) {
			t.Fatalf("bad %q: got %v", bad, err)
		}
	}
	// 不一致：产生恰好一条告警，内容只含后8位。
	wrong := strings.Repeat("abcd", 16)
	res3, err := st.Verify(context.Background(), "job-2", path, wrong)
	if err != nil || res3.Match {
		t.Fatalf("res3 = %+v, %v", res3, err)
	}
	if _, err := st.Verify(context.Background(), "job-2", path, wrong); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(dir, "alerts"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("alerts = %v, %v", entries, err)
	}
	var a alertRecord
	if err := loadJSON(filepath.Join(dir, "alerts", entries[0].Name()), &a); err != nil {
		t.Fatal(err)
	}
	if a.CheckID != "job-2" || a.Path != path ||
		a.Expected != wrong[len(wrong)-8:] || a.Actual != sum[len(sum)-8:] ||
		len(a.Expected) != 8 || len(a.Actual) != 8 || a.Time == "" {
		t.Fatalf("alert = %+v", a)
	}
	// 一致时不产生告警。
	if _, err := st.Verify(context.Background(), "job-3", path, sum); err != nil {
		t.Fatal(err)
	}
	entries, _ = os.ReadDir(filepath.Join(dir, "alerts"))
	if len(entries) != 1 {
		t.Fatalf("match should not alert, alerts = %d", len(entries))
	}
}

func TestCancelAndResume(t *testing.T) {
	st, _ := openStore(t, 4<<20)
	path := genFile(t, t.TempDir(), 200<<20, 6)
	want := refSum(t, path)

	// 算出两个检查点后取消。
	ctx, cancel := context.WithCancel(context.Background())
	var n int32
	st.afterCheckpoint = func() {
		if atomic.AddInt32(&n, 1) == 2 {
			cancel()
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Register(ctx, path)
		done <- err
	}()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	st.afterCheckpoint = nil
	p, ok := st.RegisterProgress(path)
	if !ok || p.ProcessedBytes == 0 || p.ProcessedBytes >= p.TotalBytes {
		t.Fatalf("progress = %+v ok=%v", p, ok)
	}

	// 再次发起：续算完成，结果正确。
	sum, err := st.Register(context.Background(), path)
	if err != nil || sum != want {
		t.Fatalf("resume = %s, %v want %s", sum, err, want)
	}
}

func TestModifiedDuringCompute(t *testing.T) {
	st, _ := openStore(t, 4<<20)
	dir := t.TempDir()
	path := genFile(t, dir, 200<<20, 7)

	// 算出两个检查点后改写文件（大小变化）。
	var n int32
	st.afterCheckpoint = func() {
		if atomic.AddInt32(&n, 1) == 2 {
			f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
			f.Write([]byte("tampered"))
			f.Close()
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := st.Register(context.Background(), path)
		done <- err
	}()
	if err := <-done; !errors.Is(err, ErrFileModified) {
		t.Fatalf("got %v", err)
	}
	st.afterCheckpoint = nil
	if _, ok := st.QueryRegistration(path); ok {
		t.Fatal("must not register after mid-compute modification")
	}
	// 再次发起：从头算，结果与新内容一致。
	want := refSum(t, path)
	sum, err := st.Register(context.Background(), path)
	if err != nil || sum != want {
		t.Fatalf("recompute = %s, %v want %s", sum, err, want)
	}
}

func TestConcurrentFiles(t *testing.T) {
	st, _ := openStore(t, 4<<20)
	const n = 4
	paths := make([]string, n)
	wants := make([]string, n)
	for i := 0; i < n; i++ {
		paths[i] = genFile(t, t.TempDir(), 60<<20, uint64(100+i))
		wants[i] = refSum(t, paths[i])
	}
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sum, err := st.Register(context.Background(), paths[i])
			if err == nil && sum != wants[i] {
				err = fmt.Errorf("file %d: sum mismatch", i)
			}
			if err == nil {
				wrong := strings.Repeat("0", 64)
				res, verr := st.Verify(context.Background(), fmt.Sprintf("job-%d", i), paths[i], wrong)
				if verr != nil || res.Match {
					err = fmt.Errorf("file %d: verify = %+v, %v", i, res, verr)
				}
			}
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
}
