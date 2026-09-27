package checksum

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Store 是校验和模块的入口，所有状态保存在 dir 指定的本地目录中。
//
// 目录布局：
//
//	dir/register/<key>.reg.json   导入登记结果
//	dir/register/<key>.prog.json  导入登记断点进度
//	dir/verify/<id>.json          校验记录（含结论）
//	dir/verify/<id>.prog.json     校验断点进度
//	dir/alerts/<id>.json          不一致告警（每个校验编号至多一条）
//
// 所有写入都先写临时文件、fsync、再 rename 并 fsync 目录，
// 进程在任意时刻被杀都不会留下半写的状态文件。
type Store struct {
	dir       string
	chunkSize int64 // 检查点间隔，断点续算时重复读取不超过该值

	mu    sync.Mutex
	locks map[string]*sync.Mutex // 按文件路径/校验编号串行化

	afterCheckpoint func() // 仅测试用：每次保存检查点后调用
}

// Option 用于调整 Store 的行为。
type Option func(*Store)

// WithChunkSize 设置检查点间隔（字节），默认 32 MiB。
// 每次被打断后，重复读取的数据不超过该值。
func WithChunkSize(n int64) Option {
	return func(s *Store) { s.chunkSize = n }
}

const defaultChunkSize = 32 << 20

// Open 打开（必要时创建）位于 dir 的 Store。
func Open(dir string, opts ...Option) (*Store, error) {
	s := &Store{dir: dir, chunkSize: defaultChunkSize, locks: make(map[string]*sync.Mutex)}
	for _, o := range opts {
		o(s)
	}
	if s.chunkSize <= 0 {
		return nil, fmt.Errorf("checksum: chunkSize 必须为正数")
	}
	for _, sub := range []string{"register", "verify", "alerts"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// lock 返回指定 key 的互斥锁，同一 key 的操作在进程内串行。
func (s *Store) lock(key string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.locks[key]
	if !ok {
		l = &sync.Mutex{}
		s.locks[key] = l
	}
	return l
}

// keyOf 把任意字符串（文件路径、校验编号）映射为安全的文件名。
func keyOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func (s *Store) regFile(path string) string {
	return filepath.Join(s.dir, "register", keyOf(path)+".reg.json")
}
func (s *Store) regProgFile(path string) string {
	return filepath.Join(s.dir, "register", keyOf(path)+".prog.json")
}
func (s *Store) verifyFile(checkID string) string {
	return filepath.Join(s.dir, "verify", keyOf(checkID)+".json")
}
func (s *Store) verifyProgFile(checkID string) string {
	return filepath.Join(s.dir, "verify", keyOf(checkID)+".prog.json")
}
func (s *Store) alertFile(checkID string) string {
	return filepath.Join(s.dir, "alerts", keyOf(checkID)+".json")
}

// atomicWrite 把 data 原子地写入 path：写临时文件后 rename，避免读到半写文件。
// durable 为 true 时额外 fsync 文件和目录，保证掉电/宕机不丢；
// 进程被杀（操作系统仍正常运行）时，已 write 的数据不会丢，无需 fsync。
func atomicWrite(path string, data []byte, durable bool) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if durable {
		if err := f.Sync(); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if !durable {
		return nil
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// saveJSON 原子地把 v 以 JSON 持久化写入 path（fsync + 目录 fsync）。
// 用于登记结果、校验结论、告警等不可丢失的记录。
func saveJSON(path string, v any) error {
	return saveJSONMode(path, v, true)
}

// saveJSONVolatile 原子但不 fsync 地写入 path，用于可丢失的断点进度。
func saveJSONVolatile(path string, v any) error {
	return saveJSONMode(path, v, false)
}

func saveJSONMode(path string, v any, durable bool) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return atomicWrite(path, data, durable)
}

// loadJSON 从 path 读取 JSON 到 v；文件不存在返回 os.ErrNotExist 包装的错误。
func loadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
