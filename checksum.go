// Package checksum 提供镜像文件 SHA-256 校验和的断点续算、导入登记与部署前校验能力。
// 所有进度、登记结果与告警都持久化在调用方指定的本地目录中。
package checksum

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ErrFileModified 表示文件在计算期间被修改，本次计算作废。
var ErrFileModified = errors.New("文件在计算期间被修改")

// ErrNotRegistered 表示文件没有导入登记记录。
var ErrNotRegistered = errors.New("文件未登记")

// Progress 描述一次计算的进度。
type Progress struct {
	Processed int64 // 已处理字节数
	Total     int64 // 文件总大小
	Done      bool  // 是否已有最终结论
}

// Registration 是文件的导入登记信息。
type Registration struct {
	Path     string
	Checksum string // 64 位小写十六进制 SHA-256
	Valid    bool   // false 表示文件已变化，登记值已失效
}

// VerifyResult 是一次部署前校验的结论。
type VerifyResult struct {
	Match    bool
	Expected string // 归一化为小写
	Actual   string
}

// Store 是模块入口，管理一个本地状态目录。
type Store struct {
	dir string

	mu     sync.Mutex
	locks  map[string]*sync.Mutex
	closed bool
}

// Open 打开（必要时创建）位于 dir 的状态目录。
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"", "registry", "progress", "verify", "alerts"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir, locks: make(map[string]*sync.Mutex)}, nil
}

// Close 关闭 Store，当前实现不持有需要释放的资源。
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// keyLock 返回某个键的互斥锁，保证同一键的计算串行。
func (s *Store) keyLock(key string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	lk, ok := s.locks[key]
	if !ok {
		lk = &sync.Mutex{}
		s.locks[key] = lk
	}
	return lk
}

func (s *Store) regRecordPath(abs string) string {
	sum := sha256Hex([]byte(abs))
	return filepath.Join(s.dir, "registry", "reg-"+sum+".json")
}

func (s *Store) regProgressPath(abs string) string {
	sum := sha256Hex([]byte(abs))
	return filepath.Join(s.dir, "progress", "reg-"+sum+".json")
}

func (s *Store) verifyRecordPath(checkID string) string {
	return filepath.Join(s.dir, "verify", checkID+".json")
}

func (s *Store) alertPath(checkID string) string {
	return filepath.Join(s.dir, "alerts", checkID+".json")
}

// Register 计算文件的 SHA-256 并登记。文件已登记且未变化时直接返回登记值。
// 支持断点续算；文件在计算期间被修改时返回 ErrFileModified。
func (s *Store) Register(ctx context.Context, path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	lk := s.keyLock("reg|" + abs)
	lk.Lock()
	defer lk.Unlock()

	info, err := os.Stat(abs)
	if err != nil {
		return "", err
	}
	id := statFileID(info)

	// 已登记且文件未变：直接返回登记值，不重读文件。
	var rec registrationRecord
	if err := readJSON(s.regRecordPath(abs), &rec); err == nil && rec.File == id {
		return rec.Checksum, nil
	}

	// 加载断点；文件变了则旧断点作废。
	var cp checkpoint
	if err := readJSON(s.regProgressPath(abs), &cp); err != nil || !cp.valid(id) {
		cp = checkpoint{}
	}

	sum, err := resumeCompute(ctx, abs, &cp, func(next *checkpoint) error {
		return writeJSONUnsynced(s.regProgressPath(abs), next)
	})
	if err != nil {
		if errors.Is(err, ErrFileModified) {
			// 本次计算作废，清掉断点，下次从头算。
			os.Remove(s.regProgressPath(abs))
		}
		return "", err
	}

	rec = registrationRecord{Path: abs, File: id, Checksum: sum, Time: time.Now()}
	if err := writeJSON(s.regRecordPath(abs), &rec); err != nil {
		return "", err
	}
	os.Remove(s.regProgressPath(abs))
	return sum, nil
}

// QueryRegistration 查询文件的登记值。文件已变化时返回的 Registration.Valid 为 false。
func (s *Store) QueryRegistration(path string) (Registration, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Registration{}, err
	}
	var rec registrationRecord
	if err := readJSON(s.regRecordPath(abs), &rec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Registration{}, ErrNotRegistered
		}
		return Registration{}, err
	}
	reg := Registration{Path: abs, Checksum: rec.Checksum}
	if info, err := os.Stat(abs); err == nil && statFileID(info) == rec.File {
		reg.Valid = true
	}
	return reg, nil
}

var checkIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// normalizeExpected 校验并归一化期望校验和（64 位十六进制，大小写不限）。
func normalizeExpected(expected string) (string, error) {
	if len(expected) != 64 {
		return "", fmt.Errorf("期望校验和必须是 64 位十六进制: %q", expected)
	}
	for _, c := range expected {
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return "", fmt.Errorf("期望校验和必须是 64 位十六进制: %q", expected)
		}
	}
	return strings.ToLower(expected), nil
}

// Verify 执行部署前校验：完整读取文件并与 expected 比对。
// 同一 checkID 重复调用返回同一结论；checkID 绑定的路径或期望值不同时返回错误。
func (s *Store) Verify(ctx context.Context, checkID, path, expected string) (VerifyResult, error) {
	if !checkIDPattern.MatchString(checkID) {
		return VerifyResult{}, fmt.Errorf("非法的校验编号: %q", checkID)
	}
	norm, err := normalizeExpected(expected)
	if err != nil {
		return VerifyResult{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return VerifyResult{}, err
	}
	lk := s.keyLock("ver|" + checkID)
	lk.Lock()
	defer lk.Unlock()

	vpath := s.verifyRecordPath(checkID)
	var rec verifyRecord
	exists := true
	if err := readJSON(vpath, &rec); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return VerifyResult{}, err
		}
		exists = false
		rec = verifyRecord{CheckID: checkID, Path: abs, Expected: norm}
	}
	if rec.Path != abs || rec.Expected != norm {
		return VerifyResult{}, fmt.Errorf("校验编号 %s 已绑定其他文件或期望值", checkID)
	}
	if rec.Done {
		// 已有结论：直接返回；不一致时确保告警已落盘。
		if !rec.Match {
			if err := s.ensureAlert(&rec); err != nil {
				return VerifyResult{}, err
			}
		}
		return VerifyResult{Match: rec.Match, Expected: norm, Actual: rec.Actual}, nil
	}

	info, err := os.Stat(abs)
	if err != nil {
		return VerifyResult{}, err
	}
	id := statFileID(info)
	if !rec.Check.valid(id) {
		rec.Check = nil
	}
	// 先持久化编号与路径、期望值的绑定，再开始计算。
	if !exists || rec.Check == nil {
		if err := writeJSON(vpath, &rec); err != nil {
			return VerifyResult{}, err
		}
	}

	actual, err := resumeCompute(ctx, abs, rec.Check, func(next *checkpoint) error {
		rec.Check = next
		return writeJSONUnsynced(vpath, &rec)
	})
	if err != nil {
		if errors.Is(err, ErrFileModified) {
			// 本次计算作废：清空断点从头算，不产生结论也不告警。
			rec.Check = nil
			if werr := writeJSON(vpath, &rec); werr != nil {
				return VerifyResult{}, werr
			}
		}
		return VerifyResult{}, err
	}

	rec.Done = true
	rec.Match = actual == norm
	rec.Actual = actual
	if err := writeJSON(vpath, &rec); err != nil {
		return VerifyResult{}, err
	}
	if !rec.Match {
		if err := s.ensureAlert(&rec); err != nil {
			return VerifyResult{}, err
		}
	}
	return VerifyResult{Match: rec.Match, Expected: norm, Actual: actual}, nil
}

// ensureAlert 保证该编号的不一致告警存在且只有一条（按编号命名，重复写是幂等的）。
func (s *Store) ensureAlert(rec *verifyRecord) error {
	apath := s.alertPath(rec.CheckID)
	if _, err := os.Stat(apath); err == nil {
		return nil
	}
	if beforeAlertHook != nil {
		beforeAlertHook()
	}
	alert := alertRecord{
		Path:     rec.Path,
		CheckID:  rec.CheckID,
		Expected: tail8(rec.Expected),
		Actual:   tail8(rec.Actual),
		Time:     time.Now(),
	}
	if err := writeJSON(apath, &alert); err != nil {
		return err
	}
	if afterAlertHook != nil {
		afterAlertHook()
	}
	return nil
}

// tail8 取校验和的后 8 位。
func tail8(sum string) string {
	if len(sum) <= 8 {
		return sum
	}
	return sum[len(sum)-8:]
}

// RegistrationProgress 查询文件导入登记的计算进度。
func (s *Store) RegistrationProgress(path string) (Progress, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return Progress{}, err
	}
	var rec registrationRecord
	if err := readJSON(s.regRecordPath(abs), &rec); err == nil {
		if info, serr := os.Stat(abs); serr == nil && statFileID(info) == rec.File {
			return Progress{Processed: rec.File.Size, Total: rec.File.Size, Done: true}, nil
		}
	}
	var cp checkpoint
	if err := readJSON(s.regProgressPath(abs), &cp); err == nil {
		return Progress{Processed: cp.Offset, Total: cp.File.Size}, nil
	}
	if info, serr := os.Stat(abs); serr == nil {
		return Progress{Total: info.Size()}, nil
	}
	return Progress{}, nil
}

// VerificationProgress 查询某次部署前校验的计算进度。
func (s *Store) VerificationProgress(checkID string) (Progress, error) {
	if !checkIDPattern.MatchString(checkID) {
		return Progress{}, fmt.Errorf("非法的校验编号: %q", checkID)
	}
	var rec verifyRecord
	if err := readJSON(s.verifyRecordPath(checkID), &rec); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Progress{}, fmt.Errorf("校验编号 %s 不存在", checkID)
		}
		return Progress{}, err
	}
	if rec.Check != nil {
		return Progress{Processed: rec.Check.Offset, Total: rec.Check.File.Size, Done: rec.Done}, nil
	}
	if info, err := os.Stat(rec.Path); err == nil {
		return Progress{Total: info.Size(), Done: rec.Done}, nil
	}
	return Progress{Done: rec.Done}, nil
}
