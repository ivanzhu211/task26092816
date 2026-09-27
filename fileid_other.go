//go:build !unix

package checksum

import "os"

// statFileID 在非 unix 平台上退化为大小+修改时间。
func statFileID(info os.FileInfo) fileID {
	return fileID{Size: info.Size(), Mtime: info.ModTime().UnixNano()}
}
