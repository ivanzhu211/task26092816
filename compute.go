package checksum

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"syscall"
)

// fileIdent 标识一个文件的版本：大小、修改时间、inode 任一变化都算文件变了。
type fileIdent struct {
	Size    int64
	ModNano int64
	Ino     uint64
}

// statIdent 读取路径当前的 fileIdent。
func statIdent(path string) (fileIdent, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileIdent{}, err
	}
	id := fileIdent{Size: fi.Size(), ModNano: fi.ModTime().UnixNano()}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		id.Ino = st.Ino
	}
	return id, nil
}

// progState 是断点进度：文件版本 + 已处理偏移 + SHA-256 中间状态。
type progState struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	ModNano   int64  `json:"mod_nano"`
	Ino       uint64 `json:"ino"`
	Offset    int64  `json:"offset"`
	HashState []byte `json:"hash_state"`
}

func (p *progState) ident() fileIdent {
	return fileIdent{Size: p.Size, ModNano: p.ModNano, Ino: p.Ino}
}

func (p *progState) matches(id fileIdent) bool {
	return p.Size == id.Size && p.ModNano == id.ModNano && p.Ino == id.Ino
}

const readBufSize = 1 << 20 // 1 MiB，内存占用与文件大小无关

// compute 从断点续算文件的 SHA-256，进度保存在 progFile 中。
// 成功返回小写十六进制校验和并删除进度文件。
// 计算期间文件被修改：删除进度并返回 ErrFileModified。
// ctx 取消：保存进度后返回 ctx.Err()。
func (s *Store) compute(ctx context.Context, path, progFile string) (string, error) {
	id, err := statIdent(path)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	var offset int64

	// 尝试接续上次进度；文件版本变了则旧进度作废，从头算。
	var prog progState
	if err := loadJSON(progFile, &prog); err == nil &&
		prog.Path == path && prog.matches(id) && prog.Offset >= 0 && prog.Offset <= id.Size {
		if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(prog.HashState); err == nil {
			offset = prog.Offset
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return "", err
	}

	buf := make([]byte, readBufSize)
	save := func() error {
		state, err := h.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil {
			return err
		}
		return saveJSONVolatile(progFile, &progState{
			Path: path, Size: id.Size, ModNano: id.ModNano, Ino: id.Ino,
			Offset: offset, HashState: state,
		})
	}

	chunkStart := offset
	for {
		if err := ctx.Err(); err != nil {
			save()
			return "", err
		}
		n, rerr := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
			offset += int64(n)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			save()
			return "", rerr
		}
		// 到达检查点间隔：落盘进度，并检测文件是否在计算期间被修改。
		if offset-chunkStart >= s.chunkSize {
			chunkStart = offset
			if err := save(); err != nil {
				return "", err
			}
			if s.afterCheckpoint != nil {
				s.afterCheckpoint()
			}
			cur, err := statIdent(path)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					os.Remove(progFile)
					return "", ErrFileModified
				}
				return "", err
			}
			if cur != id {
				os.Remove(progFile)
				return "", ErrFileModified
			}
		}
	}

	// 算完后再次确认文件未变，才能采信结果。
	cur, err := statIdent(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			os.Remove(progFile)
			return "", ErrFileModified
		}
		return "", err
	}
	if cur != id {
		os.Remove(progFile)
		return "", ErrFileModified
	}

	os.Remove(progFile)
	return hex.EncodeToString(h.Sum(nil)), nil
}

var _ hash.Hash = sha256.New() // 确保 hash 接口假设成立
