//go:build unix

package checksum

import (
	"os"
	"syscall"
)

// statFileID 返回文件的版本标识（大小、修改时间、inode）。
func statFileID(info os.FileInfo) fileID {
	id := fileID{Size: info.Size(), Mtime: info.ModTime().UnixNano()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		id.Ino = st.Ino
	}
	return id
}
