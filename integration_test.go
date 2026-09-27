package checksum

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestHelperProcess 是被强杀的子进程入口，不是真正的测试。
// 用法: CHECKSUM_HELPER=1 test.binary -test.run=TestHelperProcess -- \
// <statedir> <chunk> register <path>
// <statedir> <chunk> verify <path> <checkID> <expected>
func TestHelperProcess(t *testing.T) {
	if os.Getenv("CHECKSUM_HELPER") != "1" {
		return
	}
	args := os.Args
	for i, a := range args {
		if a == "--" {
			args = args[i+1:]
			break
		}
	}
	var chunk int64
	fmt.Sscanf(args[1], "%d", &chunk)
	st, err := Open(args[0], WithChunkSize(chunk))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	switch args[2] {
	case "register":
		sum, err := st.Register(context.Background(), args[3])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Println("RESULT " + sum)
	case "verify":
		res, err := st.Verify(context.Background(), args[4], args[3], args[5])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Printf("RESULT %v %s\n", res.Match, res.Actual)
	}
	os.Exit(0)
}

// runHelper 启动一个助手进程；killAfter > 0 时在随机时刻（不超过 killAfter）强杀。
// 返回 (是否被强杀, 标准输出)。
func runHelper(t *testing.T, killAfter time.Duration, args ...string) (bool, string) {
	t.Helper()
	full := append([]string{"-test.run=TestHelperProcess", "--"}, args...)
	cmd := exec.Command(os.Args[0], full...)
	cmd.Env = append(os.Environ(), "CHECKSUM_HELPER=1")
	var out, errOut strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	if killAfter > 0 {
		d := time.Duration(rand.Uint64N(uint64(killAfter)))
		timer := time.AfterFunc(d, func() {
			if cmd.Process != nil {
				cmd.Process.Kill()
			}
		})
		defer timer.Stop()
	}
	err := cmd.Wait()
	if err != nil {
		if killed || strings.Contains(err.Error(), "killed") || strings.Contains(err.Error(), "signal") {
			killed = true
		} else {
			t.Fatalf("helper failed: %v\nstderr: %s", err, errOut.String())
		}
	}
	if killed {
		return true, ""
	}
	return false, out.String()
}

// progOffset 读取断点进度文件中的偏移；文件不存在返回 fallback。
func progOffset(path string, fallback int64) int64 {
	var prog progState
	if err := loadJSON(path, &prog); err != nil {
		return fallback
	}
	return prog.Offset
}

// TestKillResumeRegister 反复强杀续算，最终结果正确且重读量有界。
func TestKillResumeRegister(t *testing.T) {
	const size = 512 << 20 // 512 MiB
	const chunk = 8 << 20  // 8 MiB 检查点，重读上界远小于 64 MiB
	st, dir := openStore(t, chunk)
	path := genFile(t, t.TempDir(), size, 1000)
	want := refSum(t, path)

	var kills int
	var lastOffset int64
	var totalReadBound int64 // 各次运行读取量上界之和
	var sum string
	for i := 0; i < 60; i++ {
		killed, out := runHelper(t, 120*time.Millisecond,
			dir, fmt.Sprint(chunk), "register", path)
		offset := progOffset(st.regProgFile(path), lastOffset)
		if killed {
			kills++
			totalReadBound += offset - lastOffset + chunk
			lastOffset = offset
			continue
		}
		totalReadBound += size - lastOffset
		sum = strings.TrimPrefix(strings.TrimSpace(out), "RESULT ")
		break
	}
	if sum == "" {
		t.Fatal("helper never completed")
	}
	if sum != want {
		t.Fatalf("sum = %s, want %s (kills=%d)", sum, want, kills)
	}
	if kills < 2 {
		t.Fatalf("expected repeated kills, got %d", kills)
	}
	limit := int64(size) + int64(kills)*64<<20
	if totalReadBound > limit {
		t.Fatalf("read bound %d exceeds limit %d (kills=%d)", totalReadBound, limit, kills)
	}
	t.Logf("kills=%d totalReadBound=%d limit=%d", kills, totalReadBound, limit)

	// 与系统 sha256sum/shasum 交叉验证（若可用）。
	if ref := systemSHA256(path); ref != "" && ref != sum {
		t.Fatalf("system sha256 = %s, got %s", ref, sum)
	}
}

// systemSHA256 调用系统工具计算 SHA-256；不可用时返回空串。
func systemSHA256(path string) string {
	for _, c := range [][]string{{"sha256sum", path}, {"shasum", "-a", "256", path}} {
		if out, err := exec.Command(c[0], c[1:]...).Output(); err == nil {
			return strings.Fields(string(out))[0]
		}
	}
	return ""
}

// TestKillThenFileReplaced 打断期间文件被同名替换，最终结果与新内容一致。
func TestKillThenFileReplaced(t *testing.T) {
	const chunk = 8 << 20
	st, dir := openStore(t, chunk)
	imgDir := t.TempDir()
	path := genFile(t, imgDir, 512<<20, 2000)

	// 先算出部分进度再强杀。
	for i := 0; i < 30; i++ {
		killed, _ := runHelper(t, 150*time.Millisecond, dir, fmt.Sprint(chunk), "register", path)
		if killed && progOffset(st.regProgFile(path), 0) > 0 {
			break
		}
	}
	if progOffset(st.regProgFile(path), 0) == 0 {
		t.Fatal("no progress saved before kill")
	}

	// 同名替换为另一个文件（不同大小、不同内容）。
	os.Remove(path)
	genFileAt(t, path, 96<<20, 3000)
	want := refSum(t, path)

	var sum string
	for i := 0; i < 40; i++ {
		killed, out := runHelper(t, 900*time.Millisecond, dir, fmt.Sprint(chunk), "register", path)
		if !killed {
			sum = strings.TrimPrefix(strings.TrimSpace(out), "RESULT ")
			break
		}
	}
	if sum != want {
		t.Fatalf("sum = %s, want %s (new content)", sum, want)
	}
	if reg, ok := st.QueryRegistration(path); !ok || reg.Stale || reg.Checksum != want {
		t.Fatalf("reg = %+v ok=%v", reg, ok)
	}
}

// genFileAt 在指定路径生成伪随机文件。
func genFileAt(t *testing.T, path string, size int64, seed uint64) {
	t.Helper()
	dir := filepath.Dir(path)
	tmp := genFile(t, dir, size, seed)
	if tmp != path {
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
}

// TestKillVerifyAlert 不一致校验被反复强杀，最终恰好一条告警。
func TestKillVerifyAlert(t *testing.T) {
	const chunk = 8 << 20
	st, dir := openStore(t, chunk)
	path := genFile(t, t.TempDir(), 128<<20, 4000)
	sum := refSum(t, path)
	wrong := strings.Repeat("ef", 32)

	var done bool
	for i := 0; i < 40; i++ {
		killed, out := runHelper(t, 900*time.Millisecond,
			dir, fmt.Sprint(chunk), "verify", path, "deploy-1", wrong)
		if !killed {
			if !strings.Contains(out, "RESULT false "+sum) {
				t.Fatalf("unexpected output: %q", out)
			}
			done = true
			break
		}
	}
	if !done {
		t.Fatal("verify never completed")
	}
	assertOneAlert(t, dir, "deploy-1", path, wrong, sum)

	// 模拟「写完告警、未写结论」时被杀：删掉结论文件，用同一编号重跑。
	if err := os.Remove(st.verifyFile("deploy-1")); err != nil {
		t.Fatal(err)
	}
	res, err := st.Verify(context.Background(), "deploy-1", path, wrong)
	if err != nil || res.Match {
		t.Fatalf("res = %+v, %v", res, err)
	}
	assertOneAlert(t, dir, "deploy-1", path, wrong, sum)

	// 已有结论后再重跑：直接返回结论，告警仍只有一条。
	res, err = st.Verify(context.Background(), "deploy-1", path, strings.ToUpper(wrong))
	if err != nil || res.Match {
		t.Fatalf("res = %+v, %v", res, err)
	}
	assertOneAlert(t, dir, "deploy-1", path, wrong, sum)
}

func assertOneAlert(t *testing.T, dir, checkID, path, expected, actual string) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "alerts"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("alerts = %v, %v", entries, err)
	}
	var a alertRecord
	if err := loadJSON(filepath.Join(dir, "alerts", entries[0].Name()), &a); err != nil {
		t.Fatal(err)
	}
	if a.CheckID != checkID || a.Path != path ||
		a.Expected != expected[len(expected)-8:] || a.Actual != actual[len(actual)-8:] {
		t.Fatalf("alert = %+v", a)
	}
}

// TestKillConcurrentFiles 多个文件同时计算，各自被打断后续算，结果全部正确。
func TestKillConcurrentFiles(t *testing.T) {
	const chunk = 8 << 20
	_, dir := openStore(t, chunk)
	const n = 3
	paths := make([]string, n)
	wants := make([]string, n)
	for i := 0; i < n; i++ {
		paths[i] = genFile(t, t.TempDir(), 96<<20, uint64(5000+i))
		wants[i] = refSum(t, paths[i])
	}

	type result struct {
		sum string
		err error
	}
	results := make([]result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for try := 0; try < 40; try++ {
				killed, out := runHelper(t, 800*time.Millisecond,
					dir, fmt.Sprint(chunk), "register", paths[i])
				if !killed {
					results[i].sum = strings.TrimPrefix(strings.TrimSpace(out), "RESULT ")
					return
				}
			}
			results[i].err = fmt.Errorf("never completed")
		}(i)
	}
	wg.Wait()
	for i := range results {
		if results[i].err != nil {
			t.Fatalf("file %d: %v", i, results[i].err)
		}
		if results[i].sum != wants[i] {
			t.Fatalf("file %d: sum = %s, want %s", i, results[i].sum, wants[i])
		}
	}
}
