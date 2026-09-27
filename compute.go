package checksum

import (
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"time"
)

// chunkSize 是断点保存的间隔，也是打断后重复读取量的上界。
var chunkSize int64 = 64 << 20 // 64 MiB

// readBufSize 是单次读取的缓冲区大小，内存占用与文件大小无关。
const readBufSize = 1 << 20 // 1 MiB

// 以下为测试钩子，生产环境保持零值。
var (
	chunkDelay      time.Duration // 每个 chunk 后的额外延迟（测试用）
	readHook        func(n int64) // 每次读取后的回调（测试用）
	beforeAlertHook func()        // 写告警前回调（测试用）
	afterAlertHook  func()        // 写告警后回调（测试用）
)

// fileID 标识一个文件版本：大小、修改时间、inode 任一变化都视为文件变了。
type fileID struct {
	Size  int64  `json:"size"`
	Mtime int64  `json:"mtime"` // UnixNano
	Ino   uint64 `json:"ino"`
}

// checkpoint 是一次可恢复计算的断点。
type checkpoint struct {
	File   fileID `json:"file"`
	Offset int64  `json:"offset"`
	State  []byte `json:"state"` // sha256 digest 的二进制序列化
}

// valid 判断断点是否仍对应当前文件。
func (c *checkpoint) valid(id fileID) bool {
	return c != nil && c.File == id && c.Offset >= 0 && c.Offset <= id.Size && len(c.State) > 0
}

// sha256Hex 返回数据的 SHA-256 十六进制，用于派生文件名。
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// resumeCompute 计算 path 的 SHA-256（64 位小写十六进制）。
// cp 非空且与当前文件匹配时从断点续算，否则从头算。
// save 在每个 chunk 边界被调用以持久化断点。
// 计算期间文件被修改时返回 ErrFileModified。
func resumeCompute(ctx context.Context, path string, cp *checkpoint, save func(*checkpoint) error) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	id := statFileID(info)

	var digest hash.Hash
	var offset int64
	if cp.valid(id) {
		digest = sha256.New()
		if err := digest.(encoding.BinaryUnmarshaler).UnmarshalBinary(cp.State); err != nil {
			return "", err
		}
		offset = cp.Offset
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return "", err
		}
	} else {
		digest = sha256.New()
	}

	buf := make([]byte, readBufSize)
	chunkStart := offset
	for offset < id.Size {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		want := int64(len(buf))
		if next := chunkStart + chunkSize; offset+want > next {
			want = next - offset
		}
		if offset+want > id.Size {
			want = id.Size - offset
		}
		n, err := io.ReadFull(f, buf[:want])
		if n > 0 {
			digest.Write(buf[:n])
			offset += int64(n)
			if readHook != nil {
				readHook(int64(n))
			}
		}
		if err != nil {
			// 提前 EOF 或读错误：文件很可能在计算期间被改写。
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				return "", ErrFileModified
			}
			return "", err
		}
		if offset-chunkStart >= chunkSize || offset == id.Size {
			// chunk 边界：先确认文件没被改，再保存断点。
			cur, serr := f.Stat()
			if serr != nil {
				return "", serr
			}
			if statFileID(cur) != id {
				return "", ErrFileModified
			}
			state, merr := digest.(encoding.BinaryMarshaler).MarshalBinary()
			if merr != nil {
				return "", merr
			}
			next := &checkpoint{File: id, Offset: offset, State: state}
			if err := save(next); err != nil {
				return "", err
			}
			chunkStart = offset
			if chunkDelay > 0 {
				time.Sleep(chunkDelay)
			}
		}
	}

	// 最终确认：整个计算期间文件未变。
	cur, err := f.Stat()
	if err != nil {
		return "", err
	}
	if statFileID(cur) != id {
		return "", ErrFileModified
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
