package checksum

import (
	"context"
	"crypto/sha256"
	"io"
	"os"
	"testing"
)

const benchFileSize = 1 << 30 // 1 GiB

func benchFile(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()
	f, err := os.Create(dir + "/bench.bin")
	if err != nil {
		b.Fatal(err)
	}
	chunk := make([]byte, 4<<20)
	for i := range chunk {
		chunk[i] = byte(i)
	}
	for w := int64(0); w < benchFileSize; w += int64(len(chunk)) {
		if _, err := f.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	f.Close()
	return f.Name()
}

// BenchmarkRawSHA256 直接算一遍 SHA-256 的基准耗时。
func BenchmarkRawSHA256(b *testing.B) {
	path := benchFile(b)
	buf := make([]byte, readBufSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f, _ := os.Open(path)
		h := sha256.New()
		io.CopyBuffer(h, f, buf)
		f.Close()
		h.Sum(nil)
	}
}

// BenchmarkComputeWithCheckpoints 带断点保存的计算耗时（默认 32 MiB 检查点）。
func BenchmarkComputeWithCheckpoints(b *testing.B) {
	path := benchFile(b)
	st, err := Open(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := st.compute(context.Background(), path, st.dir+"/bench.prog.json"); err != nil {
			b.Fatal(err)
		}
	}
}
