package checksum

import "errors"

// 文件在计算期间被修改，本次计算作废。
var ErrFileModified = errors.New("checksum: 文件在计算期间被修改")

// 期望校验和格式不合法（不是64位十六进制）。
var ErrInvalidChecksum = errors.New("checksum: 期望校验和格式不合法")

// 同一校验编号换了期望值或文件路径。
var ErrCheckConflict = errors.New("checksum: 校验编号与已有记录的期望值或文件路径不一致")

// Progress 表示一次计算的进度。
type Progress struct {
	ProcessedBytes int64 // 已处理字节数
	TotalBytes     int64 // 文件总大小
}

// Registration 表示一条导入登记结果。
type Registration struct {
	Path     string // 文件绝对路径
	Checksum string // 64位小写十六进制SHA-256
	Stale    bool   // 文件已变化，登记值已失效
}

// VerifyResult 表示一次部署前校验的结论。
type VerifyResult struct {
	CheckID  string
	Path     string
	Expected string // 归一化为小写的期望校验和
	Actual   string // 实际计算出的校验和
	Match    bool   // 是否一致
}

// Alert 表示一条不一致告警。
type Alert struct {
	CheckID  string // 校验编号
	Path     string // 文件路径
	Expected string // 期望校验和后8位
	Actual   string // 实际校验和后8位
	Time     string // RFC3339时间
}
