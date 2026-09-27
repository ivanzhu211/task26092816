package checksum

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// 本文件的测试通过子进程运行计算并在随机时刻 SIGKILL，验证断点续算与告警语义。

type helperResult struct {
	Sum    string `json:"sum,omitempty"`
	Match  bool   `json:"match,omitempty"`
	Actual string `json:"actual,omitempty"`
	Err    string `json:"err,omitempty"`
}

// TestHelperProcess 是被测试进程 re-exec 出来的计算进程，由环境变量驱动。
func TestHelperProcess(t *testing.T) {
	if os.Getenv("IC_HELPER") != "1" {
		return
	}
	if v := os.Getenv("IC_CHUNK_BYTES"); v != "" {
		n, _ := strconv.ParseInt(v, 10, 64)
		chunkSize = n
	}
	if v := os.Getenv("IC_CHUNK_DELAY_MS"); v != "" {
		n, _ := strconv.Atoi(v)
		chunkDelay = time.Duration(n) * time.Millisecond
	}
	if logPath := os.Getenv("IC_READLOG"); logPath != "" {
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		defer f.Close()
		readHook = func(n int64) { fmt.Fprintln(f, n) }
	}
	switch os.Getenv("IC_KILL_HOOK") {
	case "before-alert":
		beforeAlertHook = func() { os.Exit(1) }
	case "after-alert":
		afterAlertHook = func() { os.Exit(1) }
	}

	s, err := Open(os.Getenv("IC_DIR"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	var res helperResult
	switch os.Getenv("IC_MODE") {
	case "register":
		sum, err := s.Register(context.Background(), os.Getenv("IC_FILE"))
		if err != nil {
			res.Err = err.Error()
		} else {
			res.Sum = sum
		}
	case "verify":
		r, err := s.Verify(context.Background(), os.Getenv("IC_CHECKID"), os.Getenv("IC_FILE"), os.Getenv("IC_EXPECT"))
		if err != nil {
			res.Err = err.Error()
		} else {
			res.Match, res.Actual = r.Match, r.Actual
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown IC_MODE")
		os.Exit(2)
	}
	out, _ := json.Marshal(res)
	fmt.Printf("RESULT %s\n", out)
}

// runHelper 启动一个计算子进程；killAfter>0 时在该时长后 SIGKILL。
// 返回解析后的结果（进程被强杀时 ok=false）。
func runHelper(t *testing.T, env []string, killAfter time.Duration) (res helperResult, ok bool) {
	var shouldKill func() bool
	if killAfter > 0 {
		deadline := time.Now().Add(killAfter)
		shouldKill = func() bool { return time.Now().After(deadline) }
	}
	return runHelperEx(t, env, shouldKill)
}

// runHelperKillOnProgress 启动子进程，并在进度达到 minProcessed 字节时 SIGKILL。
func runHelperKillOnProgress(t *testing.T, env []string, progress func() (Progress, error), minProcessed int64) (helperResult, bool) {
	t.Helper()
	shouldKill := func() bool {
		p, err := progress()
		return err == nil && p.Processed >= minProcessed
	}
	return runHelperEx(t, env, shouldKill)
}

// runHelperEx 启动一个计算子进程；shouldKill 非空时轮询并在条件满足时 SIGKILL。
func runHelperEx(t *testing.T, env []string, shouldKill func() bool) (res helperResult, ok bool) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), "IC_HELPER=1", "GOCACHE="+os.Getenv("GOCACHE"))
	cmd.Env = append(cmd.Env, env...)
	var stdout, stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitCh := make(chan struct{})
	go func() { cmd.Wait(); close(waitCh) }()
	if shouldKill != nil {
		tick := time.NewTicker(5 * time.Millisecond)
		timeout := time.After(60 * time.Second)
		stop := false
		for !stop {
			select {
			case <-waitCh:
				stop = true
			case <-tick.C:
				if shouldKill() {
					cmd.Process.Kill()
					stop = true
				}
			case <-timeout:
				stop = true
			}
		}
		tick.Stop()
	}
	<-waitCh
	for _, line := range strings.Split(stdout.String(), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "RESULT ")), &res); err != nil {
				t.Fatal(err)
			}
			return res, true
		}
	}
	t.Logf("子进程未输出结果: stderr=%s", stderr.String())
	return helperResult{}, false
}

func helperEnv(dir, mode, file string, extra ...string) []string {
	env := []string{
		"IC_DIR=" + dir,
		"IC_MODE=" + mode,
		"IC_FILE=" + file,
		"IC_CHUNK_BYTES=4194304", // 4 MiB，加快测试
		"IC_CHUNK_DELAY_MS=15",   // 拉长计算窗口便于强杀
	}
	return append(env, extra...)
}

// sumReadLog 汇总子进程记录的实际读取字节数。
func sumReadLog(t *testing.T, path string) int64 {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var total int64
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	return total
}

// TestKillResumeRegister 几百 MB 随机文件，随机时刻反复强杀续算，
// 结果须与独立计算一致，总读取量不超过 文件大小 + 打断次数 × chunk。
func TestKillResumeRegister(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	f := filepath.Join(t.TempDir(), "img.bin")
	const size = 256 << 20 // 256 MiB
	writeRandomFile(t, f, size)
	want := sha256File(t, f)
	readlog := filepath.Join(t.TempDir(), "read.log")

	const chunk = 4 << 20
	kills := 0
	var res helperResult
	var ok bool
	for attempt := 0; attempt < 8; attempt++ {
		env := helperEnv(stateDir, "register", f, "IC_READLOG="+readlog)
		killAfter := time.Duration(0)
		if kills < 4 {
			killAfter = time.Duration(100+rand.Intn(800)) * time.Millisecond
		}
		res, ok = runHelper(t, env, killAfter)
		if ok {
			break
		}
		kills++
		// 强杀后应留下可查询的中间进度。
		s, err := Open(stateDir)
		if err != nil {
			t.Fatal(err)
		}
		p, err := s.RegistrationProgress(f)
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if p.Done || p.Total != size {
			t.Fatalf("强杀后进度异常: %+v", p)
		}
	}
	if !ok {
		t.Fatal("多次尝试后仍未完成")
	}
	if kills < 2 {
		t.Fatalf("应至少发生 2 次打断, 实际 %d", kills)
	}
	if res.Err != "" {
		t.Fatalf("计算失败: %s", res.Err)
	}
	if res.Sum != want {
		t.Fatalf("续算结果错误: got %s want %s", res.Sum, want)
	}
	total := sumReadLog(t, readlog)
	if limit := int64(size) + int64(kills)*chunk; total > limit {
		t.Fatalf("总读取量超限: got %d, limit %d (kills=%d)", total, limit, kills)
	}
	t.Logf("kills=%d totalRead=%d size=%d", kills, total, size)
}

// TestKillThenFileChanged 打断之间文件被改写/同名替换，最终结果须与新内容一致。
func TestKillThenFileChanged(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	dir := t.TempDir()
	f := filepath.Join(dir, "img.bin")
	writeRandomFile(t, f, 64<<20)

	s, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	regProgress := func() (Progress, error) { return s.RegistrationProgress(f) }

	// 第一次计算被强杀，留下旧文件的断点。
	if _, ok := runHelperKillOnProgress(t, helperEnv(stateDir, "register", f), regProgress, 8<<20); ok {
		t.Fatal("第一次运行应被强杀")
	}

	// 打断期间：文件被改写。
	writeRandomFile(t, f, 64<<20)
	want := sha256File(t, f)
	res, ok := runHelper(t, helperEnv(stateDir, "register", f), 0)
	if !ok || res.Err != "" || res.Sum != want {
		t.Fatalf("改写后续算结果错误: %+v ok=%v want=%s", res, ok, want)
	}

	// 先改写文件使登记失效，再次计算并强杀，留下新内容的断点。
	writeRandomFile(t, f, 96<<20)
	if _, ok := runHelperKillOnProgress(t, helperEnv(stateDir, "register", f), regProgress, 8<<20); ok {
		t.Fatal("第三次运行应被强杀")
	}
	// 打断期间：同路径替换为另一个文件。
	repl := filepath.Join(dir, "img.bin.new")
	writeRandomFile(t, repl, 96<<20)
	fi, _ := os.Stat(f)
	os.Chtimes(repl, fi.ModTime(), fi.ModTime()) // 连修改时间都伪装成一样
	if err := os.Rename(repl, f); err != nil {
		t.Fatal(err)
	}
	want = sha256File(t, f)
	res, ok = runHelper(t, helperEnv(stateDir, "register", f), 0)
	if !ok || res.Err != "" || res.Sum != want {
		t.Fatalf("替换后续算结果错误: %+v ok=%v want=%s", res, ok, want)
	}
}

// TestKillModifiedDuringCompute 计算过程中文件被改写，须报告修改且不登记。
func TestKillModifiedDuringCompute(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 64<<20)

	s, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// 等计算推进到 8 MiB 后改写文件，确保改在计算过程中。
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			p, err := s.RegistrationProgress(f)
			if err == nil && p.Processed >= 8<<20 {
				writeRandomFile(t, f, 64<<20)
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	res, ok := runHelper(t, helperEnv(stateDir, "register", f), 0)
	<-done
	if !ok {
		t.Fatal("子进程应正常退出并报告错误")
	}
	if res.Err != "文件在计算期间被修改" {
		t.Fatalf("应报告文件被修改, got %q", res.Err)
	}
	if _, err := s.QueryRegistration(f); err == nil {
		t.Fatal("计算期间被修改不应登记任何结果")
	}
}

// TestKillAlertExactlyOnce 不一致校验在写告警前后分别被强杀，最终恰好一条告警。
func TestKillAlertExactlyOnce(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	f := filepath.Join(t.TempDir(), "img.bin")
	writeRandomFile(t, f, 64<<20)
	actual := sha256File(t, f)
	wrong := strings.Repeat("0", 64)
	env := func(extra ...string) []string {
		base := []string{"IC_CHECKID=deploy-42", "IC_EXPECT=" + wrong}
		return helperEnv(stateDir, "verify", f, append(base, extra...)...)
	}

	s, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	verProgress := func() (Progress, error) { return s.VerificationProgress("deploy-42") }

	// 第 1 次：计算中途被强杀。
	if _, ok := runHelperKillOnProgress(t, env(), verProgress, 8<<20); ok {
		t.Fatal("第 1 次运行应被强杀")
	}
	// 第 2 次：结论已算出，在写告警之前退出（模拟强杀）。
	if _, ok := runHelper(t, env("IC_KILL_HOOK=before-alert"), 0); ok {
		t.Fatal("第 2 次运行应在写告警前退出")
	}
	// 第 3 次：写完告警后、返回前退出（模拟强杀）。
	if _, ok := runHelper(t, env("IC_KILL_HOOK=after-alert"), 0); ok {
		t.Fatal("第 3 次运行应在写告警后退出")
	}
	// 第 4 次：正常返回结论。
	res, ok := runHelper(t, env(), 0)
	if !ok || res.Err != "" {
		t.Fatalf("第 4 次运行失败: %+v ok=%v", res, ok)
	}
	if res.Match || res.Actual != actual {
		t.Fatalf("结论错误: %+v", res)
	}

	entries, err := os.ReadDir(filepath.Join(stateDir, "alerts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("告警应恰好一条, got %d", len(entries))
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "alerts", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var alert alertRecord
	if err := json.Unmarshal(data, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.CheckID != "deploy-42" || alert.Actual != tail8(actual) || alert.Expected != tail8(wrong) {
		t.Fatalf("告警内容错误: %+v", alert)
	}
}

// TestKillConcurrentFiles 多个文件同时计算，各自被打断后续算，结果全部正确。
func TestKillConcurrentFiles(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	dir := t.TempDir()
	const n = 3
	files := make([]string, n)
	wants := make([]string, n)
	for i := 0; i < n; i++ {
		files[i] = filepath.Join(dir, fmt.Sprintf("img-%d.bin", i))
		writeRandomFile(t, files[i], int64(64+(i*32))<<20)
		wants[i] = sha256File(t, files[i])
	}

	s, err := Open(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// 并发启动，全部在计算中途强杀。
	var wg sync.WaitGroup
	results := make([]helperResult, n)
	oks := make([]bool, n)
	run := func(i int, kill bool) {
		defer wg.Done()
		env := helperEnv(stateDir, "register", files[i])
		if kill {
			f := files[i]
			results[i], oks[i] = runHelperKillOnProgress(t, env, func() (Progress, error) {
				return s.RegistrationProgress(f)
			}, 8<<20)
		} else {
			results[i], oks[i] = runHelper(t, env, 0)
		}
	}
	for round := 0; round < 2; round++ {
		for i := 0; i < n; i++ {
			wg.Add(1)
			go run(i, round == 0)
		}
		wg.Wait()
		if round == 0 {
			for i := 0; i < n; i++ {
				if oks[i] {
					t.Fatalf("第 0 轮文件 %d 应被强杀", i)
				}
			}
		}
	}
	for i := 0; i < n; i++ {
		if !oks[i] || results[i].Err != "" || results[i].Sum != wants[i] {
			t.Fatalf("文件 %d 结果错误: %+v ok=%v want=%s", i, results[i], oks[i], wants[i])
		}
	}
}
