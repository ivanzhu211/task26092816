package checksum

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// registrationRecord 是登记记录的持久化形式。
type registrationRecord struct {
	Path     string    `json:"path"`
	File     fileID    `json:"file"`
	Checksum string    `json:"checksum"`
	Time     time.Time `json:"time"`
}

// verifyRecord 是一次部署前校验的持久化状态，包含断点。
type verifyRecord struct {
	CheckID  string      `json:"check_id"`
	Path     string      `json:"path"` // 绝对路径
	Expected string      `json:"expected"`
	Done     bool        `json:"done"`
	Match    bool        `json:"match"`
	Actual   string      `json:"actual,omitempty"`
	Check    *checkpoint `json:"checkpoint,omitempty"`
}

// alertRecord 是一条不一致告警，校验和只保留后 8 位。
type alertRecord struct {
	Path     string    `json:"path"`
	CheckID  string    `json:"check_id"`
	Expected string    `json:"expected"` // 后 8 位
	Actual   string    `json:"actual"`   // 后 8 位
	Time     time.Time `json:"time"`
}

// atomicWriteFile 通过 临时文件+rename 原子地写文件；fsync 为 true 时额外保证落盘。
// 断点等高频写入不需要 fsync：进程被杀不会丢已写入的数据（操作系统不宕机），
// 丢掉断点最多从头重算，属于安全方向。
func atomicWriteFile(path string, data []byte, fsync bool) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if fsync {
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	if !fsync {
		return nil
	}
	return syncDir(filepath.Dir(path))
}

// syncDir fsync 目录，保证其中的 rename 结果落盘。
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// readJSON 读取并解析 JSON 文件；文件不存在时返回 os.ErrNotExist 包装错误。
func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// writeJSON 原子地写入 JSON 文件并 fsync（用于登记、结论、告警等关键记录）。
func writeJSON(path string, v any) error {
	return writeJSONSync(path, v, true)
}

// writeJSONUnsynced 原子地写入 JSON 文件但不 fsync（用于高频断点保存）。
func writeJSONUnsynced(path string, v any) error {
	return writeJSONSync(path, v, false)
}

func writeJSONSync(path string, v any, fsync bool) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, fsync)
}
