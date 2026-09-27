package checksum

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// BenchmarkPlainSHA256 直接对文件算一遍 SHA-256 的基准。
func BenchmarkPlainSHA256(b *testing.B) {
	f := filepath.Join(b.TempDir(), "img.bin")
	writeRandomFile(&testing.T{}, f, 1<<30) // 1 GiB
	buf := make([]byte, readBufSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r, err := os.Open(f)
		if err != nil {
			b.Fatal(err)
		}
		h := sha256.New()
		if _, err := io.CopyBuffer(h, r, buf); err != nil {
			b.Fatal(err)
		}
		r.Close()
	}
}

// BenchmarkResumeCompute 带断点保存的完整计算，验证额外耗时占比。
func BenchmarkResumeCompute(b *testing.B) {
	f := filepath.Join(b.TempDir(), "img.bin")
	writeRandomFile(&testing.T{}, f, 1<<30) // 1 GiB
	cpPath := filepath.Join(b.TempDir(), "cp.json")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var cp checkpoint
		_, err := resumeCompute(context.Background(), f, &cp, func(next *checkpoint) error {
			return writeJSONUnsynced(cpPath, next)
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}
