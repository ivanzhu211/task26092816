package checksum

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// writeRandomFile 生成指定大小的随机内容文件。
func writeRandomFile(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	buf := make([]byte, 1<<20)
	for written := int64(0); written < size; {
		n := int64(len(buf))
		if size-written < n {
			n = size - written
		}
		if _, err := rand.Read(buf[:n]); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			t.Fatal(err)
		}
		written += n
	}
}

// sha256File 用 crypto/sha256 独立计算文件校验和作为参照。
func sha256File(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sha256sumTool 用系统工具计算，保证与 sha256sum 完全一致。
func sha256sumTool(t *testing.T, path string) string {
	t.Helper()
	var out []byte
	var err error
	if out, err = exec.Command("sha256sum", path).Output(); err != nil {
		out, err = exec.Command("shasum", "-a", "256", path).Output()
	}
	if err != nil {
		t.Skip("系统无 sha256sum/shasum 工具")
	}
	return strings.Fields(string(out))[0]
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRegisterAndQuery(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 3<<20+12345)
	want := sha256File(t, f)

	sum, err := s.Register(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if sum != want {
		t.Fatalf("校验和错误: got %s want %s", sum, want)
	}
	if got := sha256sumTool(t, f); got != sum {
		t.Fatalf("与系统工具不一致: got %s want %s", sum, got)
	}

	// 再次登记：文件未变，不应重读。
	var reads atomic.Int64
	readHook = func(n int64) { reads.Add(n) }
	defer func() { readHook = nil }()
	sum2, err := s.Register(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if sum2 != sum {
		t.Fatal("重复登记结果不一致")
	}
	if reads.Load() != 0 {
		t.Fatalf("文件未变却重读了 %d 字节", reads.Load())
	}

	reg, err := s.QueryRegistration(f)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Valid || reg.Checksum != sum {
		t.Fatalf("登记查询错误: %+v", reg)
	}

	p, err := s.RegistrationProgress(f)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Done || p.Processed != p.Total || p.Total != 3<<20+12345 {
		t.Fatalf("进度错误: %+v", p)
	}
}

func TestRegisterFileChanged(t *testing.T) {
	s := newStore(t)
	dir := t.TempDir()
	f := filepath.Join(dir, "img.bin")
	writeRandomFile(t, f, 1<<20)
	sum1, err := s.Register(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}

	// 改写文件后，登记值应失效。
	time.Sleep(2 * time.Millisecond)
	writeRandomFile(t, f, 1<<20+1)
	reg, err := s.QueryRegistration(f)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Valid {
		t.Fatal("文件已变化，登记值应失效")
	}

	sum2, err := s.Register(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if sum2 == sum1 || sum2 != sha256File(t, f) {
		t.Fatal("文件变化后应重新计算并覆盖登记")
	}

	// 同路径替换为另一个文件（rename，inode 变化）。
	writeRandomFile(t, f+".new", 1<<20+1)
	fi, _ := os.Stat(f)
	os.Chtimes(f+".new", fi.ModTime(), fi.ModTime())
	if err := os.Rename(f+".new", f); err != nil {
		t.Fatal(err)
	}
	reg, err = s.QueryRegistration(f)
	if err != nil {
		t.Fatal(err)
	}
	if reg.Valid {
		t.Fatal("同路径替换文件后登记值应失效")
	}
}

func TestQueryNotRegistered(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 1024)
	if _, err := s.QueryRegistration(f); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("应返回 ErrNotRegistered, got %v", err)
	}
}

func TestVerifyBasic(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 2<<20)
	sum := sha256File(t, f)

	// 大写期望值也应接受。
	res, err := s.Verify(context.Background(), "job-1", f, strings.ToUpper(sum))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match || res.Actual != sum || res.Expected != sum {
		t.Fatalf("校验结论错误: %+v", res)
	}

	// 重复发起：直接返回结论，不重读文件。
	var reads atomic.Int64
	readHook = func(n int64) { reads.Add(n) }
	defer func() { readHook = nil }()
	res2, err := s.Verify(context.Background(), "job-1", f, sum)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Match || reads.Load() != 0 {
		t.Fatalf("已有结论不应重读文件: %+v reads=%d", res2, reads.Load())
	}

	p, err := s.VerificationProgress("job-1")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Done || p.Processed != p.Total {
		t.Fatalf("进度错误: %+v", p)
	}
}

func TestVerifyMismatchAlert(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 1<<20)
	actual := sha256File(t, f)
	wrong := strings.Repeat("0", 64)

	res, err := s.Verify(context.Background(), "job-2", f, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if res.Match || res.Actual != actual {
		t.Fatalf("结论错误: %+v", res)
	}

	data, err := os.ReadFile(s.alertPath("job-2"))
	if err != nil {
		t.Fatal("不一致应产生告警")
	}
	var alert alertRecord
	if err := json.Unmarshal(data, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.CheckID != "job-2" || alert.Expected != tail8(wrong) || alert.Actual != tail8(actual) {
		t.Fatalf("告警内容错误: %+v", alert)
	}
	if len(alert.Expected) != 8 || len(alert.Actual) != 8 {
		t.Fatal("告警中校验和应只显示后 8 位")
	}

	// 重复发起同一编号：仍只有一条告警。
	if _, err := s.Verify(context.Background(), "job-2", f, wrong); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(s.dir, "alerts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("告警应恰好一条, got %d", len(entries))
	}
}

func TestVerifyRejects(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 1<<20)
	sum := sha256File(t, f)

	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("0", 63)} {
		if _, err := s.Verify(context.Background(), "job-x", f, bad); err == nil {
			t.Fatalf("格式错误的期望值应被拒绝: %q", bad)
		}
	}
	if _, err := s.Verify(context.Background(), "bad/id", f, sum); err == nil {
		t.Fatal("非法校验编号应被拒绝")
	}

	if _, err := s.Verify(context.Background(), "job-3", f, sum); err != nil {
		t.Fatal(err)
	}
	// 同一编号换期望值或路径：拒绝。
	if _, err := s.Verify(context.Background(), "job-3", f, strings.Repeat("1", 64)); err == nil {
		t.Fatal("同一编号换期望值应被拒绝")
	}
	f2 := filepath.Join(t.TempDir(), "other.bin")
	writeRandomFile(t, f2, 1<<20)
	if _, err := s.Verify(context.Background(), "job-3", f2, sum); err == nil {
		t.Fatal("同一编号换路径应被拒绝")
	}
}

func TestCancelAndResume(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 16<<20)

	oldChunk, oldDelay := chunkSize, chunkDelay
	chunkSize, chunkDelay = 1<<20, 20*time.Millisecond
	defer func() { chunkSize, chunkDelay = oldChunk, oldDelay }()

	ctx, cancel := context.WithCancel(context.Background())
	var reads atomic.Int64
	readHook = func(n int64) { reads.Add(n) }
	defer func() { readHook = nil }()
	go func() { time.Sleep(150 * time.Millisecond); cancel() }()

	if _, err := s.Register(ctx, f); !errors.Is(err, context.Canceled) {
		t.Fatalf("应返回取消错误, got %v", err)
	}
	p, err := s.RegistrationProgress(f)
	if err != nil {
		t.Fatal(err)
	}
	if p.Done || p.Processed == 0 || p.Total != 16<<20 {
		t.Fatalf("取消后应有中间进度: %+v", p)
	}

	// 续算完成，结果正确。
	sum, err := s.Register(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if sum != sha256File(t, f) {
		t.Fatal("续算结果错误")
	}
	// 重复读取不超过一个 chunk。
	if total := reads.Load(); total > (16<<20)+chunkSize {
		t.Fatalf("重复读取超限: 总读取 %d", total)
	}
}

func TestModifiedDuringCompute(t *testing.T) {
	s := newStore(t)
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 16<<20)

	oldChunk, oldDelay := chunkSize, chunkDelay
	chunkSize, chunkDelay = 1<<20, 30*time.Millisecond
	defer func() { chunkSize, chunkDelay = oldChunk, oldDelay }()

	rewritten := make(chan struct{})
	go func() {
		defer close(rewritten)
		time.Sleep(120 * time.Millisecond)
		writeRandomFile(t, f, 16<<20)
	}()
	_, err := s.Register(context.Background(), f)
	if !errors.Is(err, ErrFileModified) {
		t.Fatalf("应报告文件被修改, got %v", err)
	}
	<-rewritten // 等改写彻底结束，避免影响后续断言
	if err.Error() != "文件在计算期间被修改" {
		t.Fatalf("错误文案不符: %v", err)
	}
	// 不应登记任何结果。
	if _, err := s.QueryRegistration(f); !errors.Is(err, ErrNotRegistered) {
		t.Fatalf("不应有登记结果, got %v", err)
	}
	// 也不应产生告警。
	entries, _ := os.ReadDir(filepath.Join(s.dir, "alerts"))
	if len(entries) != 0 {
		t.Fatal("不应产生告警")
	}
	// 再次发起：从头算并成功。
	sum, err := s.Register(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	if sum != sha256File(t, f) {
		t.Fatal("重新计算结果错误")
	}
}

func TestConcurrentFiles(t *testing.T) {
	s := newStore(t)
	dir := t.TempDir()
	const n = 4
	sums := make([]string, n)
	errs := make(chan error, n*2)
	for i := 0; i < n; i++ {
		f := filepath.Join(dir, strings.Repeat(string(rune('a'+i)), 1)+".bin")
		writeRandomFile(t, f, int64((2+i)<<20))
		sums[i] = sha256File(t, f)
		go func(i int, f string) {
			sum, err := s.Register(context.Background(), f)
			if err == nil && sum != sums[i] {
				err = errors.New("校验和错误")
			}
			errs <- err
		}(i, f)
		go func(i int, f string) {
			_, err := s.Verify(context.Background(), "job-conc-"+string(rune('0'+i)), f, sums[i])
			errs <- err
		}(i, f)
	}
	for i := 0; i < n*2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
