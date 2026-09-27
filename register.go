package checksum

import "context"

// regRecord 是落盘的导入登记记录，带登记时的文件版本。
type regRecord struct {
	Path     string `json:"path"`
	Checksum string `json:"checksum"`
	Size     int64  `json:"size"`
	ModNano  int64  `json:"mod_nano"`
	Ino      uint64 `json:"ino"`
}

func (r *regRecord) matches(id fileIdent) bool {
	return r.Size == id.Size && r.ModNano == id.ModNano && r.Ino == id.Ino
}

// Register 计算并登记文件的 SHA-256。
// 文件已登记且未变化时直接返回登记值，不重读文件；文件变了则重新计算并覆盖。
func (s *Store) Register(ctx context.Context, path string) (string, error) {
	l := s.lock("reg:" + path)
	l.Lock()
	defer l.Unlock()

	id, err := statIdent(path)
	if err != nil {
		return "", err
	}

	var reg regRecord
	if err := loadJSON(s.regFile(path), &reg); err == nil &&
		reg.Path == path && reg.matches(id) {
		return reg.Checksum, nil
	}

	sum, err := s.compute(ctx, path, s.regProgFile(path))
	if err != nil {
		return "", err
	}

	// 计算成功后原子登记；此刻被杀只会丢结果，不会登记错误值。
	if err := saveJSON(s.regFile(path), &regRecord{
		Path: path, Checksum: sum,
		Size: id.Size, ModNano: id.ModNano, Ino: id.Ino,
	}); err != nil {
		return "", err
	}
	return sum, nil
}

// QueryRegistration 查询文件的登记值。
// found 为 false 表示从未登记；返回值的 Stale 为 true 表示文件已变化、登记值已失效。
func (s *Store) QueryRegistration(path string) (Registration, bool) {
	l := s.lock("reg:" + path)
	l.Lock()
	defer l.Unlock()

	var reg regRecord
	if err := loadJSON(s.regFile(path), &reg); err != nil {
		return Registration{}, false
	}
	r := Registration{Path: reg.Path, Checksum: reg.Checksum}
	id, err := statIdent(path)
	if err != nil || !reg.matches(id) {
		r.Stale = true
	}
	return r, true
}

// RegisterProgress 查询导入登记的进度。
// 有未完成进度时返回断点位置；已登记且未失效时返回 100%。
func (s *Store) RegisterProgress(path string) (Progress, bool) {
	var prog progState
	if err := loadJSON(s.regProgFile(path), &prog); err == nil {
		return Progress{ProcessedBytes: prog.Offset, TotalBytes: prog.Size}, true
	}
	if reg, ok := s.QueryRegistration(path); ok && !reg.Stale {
		if id, err := statIdent(path); err == nil {
			return Progress{ProcessedBytes: id.Size, TotalBytes: id.Size}, true
		}
	}
	return Progress{}, false
}
