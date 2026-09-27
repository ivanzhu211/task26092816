# imagechecksum

镜像文件 SHA-256 校验和库（无接口层），供镜像工厂的导入流程和部署前检查调用。
所有状态（计算进度、登记结果、告警）都保存在调用方指定的本地目录中，不依赖任何外部服务。

## 用法

```go
st, err := checksum.Open("/var/lib/imagefactory/checksum-state")

// 导入登记：文件已登记且未变化时直接返回登记值，不重读文件
sum, err := st.Register(ctx, "/images/win11-golden.vhdx")

// 查询登记值：文件已变化时 Stale=true，登记值已失效
reg, ok := st.QueryRegistration(path)

// 部署前校验：完整重读文件比对，不用登记值代替
res, err := st.Verify(ctx, "deploy-job-42", path, expectedHex)

// 进度查询
p, ok := st.RegisterProgress(path)   // p.ProcessedBytes / p.TotalBytes
p, ok = st.VerifyProgress("deploy-job-42")
```

## 设计要点

- **断点续算**：`crypto/sha256` 的哈希中间状态可序列化，每 32 MiB（`WithChunkSize` 可调）
  把「哈希状态 + 偏移 + 文件版本」原子落盘。被打断（进程被杀或 ctx 取消）后再次发起，
  从最近检查点继续，重复读取不超过一个检查点间隔（< 64 MiB）。
- **文件版本**：大小 + mtime + inode 任一变化即视为文件变了，旧进度/旧登记作废。
  计算期间每个检查点和结束时各核对一次，发现变化返回 `ErrFileModified`，
  本次作废，不登记、不告警。
- **崩溃安全**：所有状态文件先写临时文件再 rename，不会留下半写文件。
  登记结果、校验结论、告警额外 fsync（文件+目录）；断点进度可丢失，不 fsync，
  因此保存进度的额外耗时几乎为零（实测远低于直算 SHA-256/256 耗时的 20%）。
- **告警恰好一次**：不一致时先写告警文件（按校验编号命名、幂等覆盖），再记校验结论。
  两步之间被杀，重跑会重写同名告警文件，不漏不重。告警中校验和只保留后 8 位。
- **校验幂等**：同一校验编号已有结论直接返回；换了期望值或文件路径返回
  `ErrCheckConflict`；期望校验和不是 64 位十六进制返回 `ErrInvalidChecksum`。
- **并发**：不同文件、不同校验编号互不等待（按 key 加锁）；内存占用恒定
  （1 MiB 读缓冲），与文件大小无关。

## 状态目录布局

```
<dir>/register/<key>.reg.json   导入登记结果（含登记时文件版本）
<dir>/register/<key>.prog.json  导入登记断点进度
<dir>/verify/<id>.json          校验记录与结论
<dir>/verify/<id>.prog.json     校验断点进度
<dir>/alerts/<id>.json          不一致告警（每个校验编号至多一条）
```

## 测试

```sh
go test ./...          # 单元测试 + 子进程强杀集成测试
go test -bench . .     # 断点保存开销基准（对比裸 SHA-256）
```

集成测试通过 `CHECKSUM_HELPER=1` 重入测试二进制模拟真实进程强杀，覆盖：
反复强杀续算（结果与 sha256sum 一致、重读量有界）、打断期间文件被替换、
计算期间文件被改写、告警写盘前后被杀（恰好一条告警）、多文件并发各自断点续算。
