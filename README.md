# imagechecksum

镜像文件 SHA-256 校验和模块（Go 库，无接口层）。供镜像工厂的导入流程与部署前检查调用。
计算进度、登记结果和告警全部持久化在调用方指定的本地目录中，只依赖本地文件系统。

## 能力

- **导入登记** `Register`：计算整个文件的标准 SHA-256（64 位小写十六进制，与 `sha256sum` 一致）并登记。
  文件已登记且未变化时直接返回登记值，不重读文件；文件变了重新计算并覆盖。
- **登记查询** `QueryRegistration`：文件已变化时返回 `Valid=false`，明确告知登记值已失效。
- **部署前校验** `Verify`：完整重读文件并与期望值比对（64 位十六进制，大小写不限，格式错误直接拒绝）。
  同一校验编号重复发起算同一次校验：已有结论直接返回，没有就接着算；编号绑定的路径或期望值不同时拒绝。
- **断点续算**：进程被杀或调用方取消（`context`）后，再次发起可从上次的断点继续，
  每次打断重复读取不超过 64 MiB。
- **变更检测**：文件大小、修改时间、inode 任一变化都视为文件变了，旧进度作废从头算；
  计算过程中文件被修改则本次计算作废，返回 `ErrFileModified`（"文件在计算期间被修改"），不登记也不告警。
- **告警**：校验结论不一致时在 `alerts/` 下产生一条告警（路径、编号、期望值/实际值后 8 位、时间），
  同一编号无论被打断多少次，告警恰好一条。
- **进度查询** `RegistrationProgress` / `VerificationProgress`：已处理字节数与文件总大小。

## 用法

```go
s, _ := checksum.Open("/var/lib/imagefactory/checksum-state")
defer s.Close()

// 导入登记
sum, err := s.Register(ctx, "/images/win-golden.qcow2")

// 查询登记值
reg, err := s.QueryRegistration("/images/win-golden.qcow2")
if err == nil && !reg.Valid {
    // 登记值已失效，文件变了
}

// 部署前校验
res, err := s.Verify(ctx, "deploy-job-1024", "/images/win-golden.qcow2", expectedHex)
if err == nil && !res.Match {
    // 不一致，alerts/deploy-job-1024.json 已生成
}
```

## 状态目录布局

```
<dir>/
  registry/   导入登记（按文件路径散列命名，原子写）
  progress/   导入计算的断点
  verify/     每个校验编号的状态与断点
  alerts/     不一致告警（按校验编号命名，幂等）
```

所有状态文件通过 临时文件+rename 原子写入；关键记录（登记、结论、告警）带 fsync，
高频断点写入不 fsync（进程被杀不丢已写入数据，丢断点最多从头重算）。

## 非功能特性

- 单文件最大 200 GB，读取缓冲区固定 1 MiB，内存占用与文件大小无关。
- 断点保存开销基准：见 `BenchmarkResumeCompute` vs `BenchmarkPlainSHA256`（远低于 20% 上限）。
- 不同文件、不同校验编号的计算互不等待（按键加锁）。

## 测试

```sh
go test ./...          # 单元测试 + 子进程强杀续算测试
go test -race ./...
go test -run xxx -bench . -benchtime 5x   # 断点开销基准
```

强杀测试通过 re-exec 测试进程并在随机时刻 SIGKILL，覆盖：反复打断续算（结果与独立计算一致、
总读取量有界）、打断期间文件被改写/同名替换、计算期间文件被修改、告警写前写后强杀恰好一条告警、
多文件并发打断续算。
