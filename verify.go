package checksum

import (
	"context"
	"encoding/hex"
	"strings"
	"time"
)

// verifyRecord 是落盘的校验记录；Done 为 true 后结论不可变。
type verifyRecord struct {
	CheckID  string `json:"check_id"`
	Path     string `json:"path"`
	Expected string `json:"expected"` // 小写
	Done     bool   `json:"done"`
	Match    bool   `json:"match"`
	Actual   string `json:"actual"`
	Size     int64  `json:"size"`
}

// alertRecord 是落盘的告警；校验和只保留后8位。
type alertRecord struct {
	CheckID  string `json:"check_id"`
	Path     string `json:"path"`
	Expected string `json:"expected"`
	Actual   string `json:"actual"`
	Time     string `json:"time"`
}

// normalizeExpected 校验并归一化期望校验和：64位十六进制，大小写不限。
func normalizeExpected(expected string) (string, error) {
	if len(expected) != 64 {
		return "", ErrInvalidChecksum
	}
	lower := strings.ToLower(expected)
	if _, err := hex.DecodeString(lower); err != nil {
		return "", ErrInvalidChecksum
	}
	return lower, nil
}

func last8(s string) string {
	if len(s) > 8 {
		return s[len(s)-8:]
	}
	return s
}

// Verify 执行部署前校验：完整读取文件并与期望校验和比对。
// 同一 checkID 重复发起算同一次校验：已有结论直接返回，没有则接着算；
// 换了期望值或文件路径返回 ErrCheckConflict。
func (s *Store) Verify(ctx context.Context, checkID, path, expected string) (VerifyResult, error) {
	exp, err := normalizeExpected(expected)
	if err != nil {
		return VerifyResult{}, err
	}

	l := s.lock("verify:" + checkID)
	l.Lock()
	defer l.Unlock()

	vf := s.verifyFile(checkID)
	var rec verifyRecord
	if err := loadJSON(vf, &rec); err == nil {
		if rec.Path != path || rec.Expected != exp {
			return VerifyResult{}, ErrCheckConflict
		}
		if rec.Done {
			return VerifyResult{
				CheckID: rec.CheckID, Path: rec.Path,
				Expected: rec.Expected, Actual: rec.Actual, Match: rec.Match,
			}, nil
		}
	}

	actual, err := s.compute(ctx, path, s.verifyProgFile(checkID))
	if err != nil {
		return VerifyResult{}, err
	}
	match := actual == exp

	// 先落告警再记结论：两步之间被杀，重跑会重写同名告警文件，
	// 保证同一编号恰好一条告警，不漏不重。
	if !match {
		if err := saveJSON(s.alertFile(checkID), &alertRecord{
			CheckID: checkID, Path: path,
			Expected: last8(exp), Actual: last8(actual),
			Time: time.Now().UTC().Format(time.RFC3339),
		}); err != nil {
			return VerifyResult{}, err
		}
	}

	var size int64
	if id, err := statIdent(path); err == nil {
		size = id.Size
	}
	rec = verifyRecord{
		CheckID: checkID, Path: path, Expected: exp,
		Done: true, Match: match, Actual: actual, Size: size,
	}
	if err := saveJSON(vf, &rec); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{
		CheckID: checkID, Path: path,
		Expected: exp, Actual: actual, Match: match,
	}, nil
}

// VerifyProgress 查询一次校验的进度。
// 有未完成进度时返回断点位置；已有结论时返回 100%。
func (s *Store) VerifyProgress(checkID string) (Progress, bool) {
	var prog progState
	if err := loadJSON(s.verifyProgFile(checkID), &prog); err == nil {
		return Progress{ProcessedBytes: prog.Offset, TotalBytes: prog.Size}, true
	}
	var rec verifyRecord
	if err := loadJSON(s.verifyFile(checkID), &rec); err == nil && rec.Done {
		return Progress{ProcessedBytes: rec.Size, TotalBytes: rec.Size}, true
	}
	return Progress{}, false
}
