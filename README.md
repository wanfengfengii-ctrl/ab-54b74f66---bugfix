# 冷冻电镜采集包 · 断点续传封存台

TypeScript/React 前端 + FastAPI 后端的全栈封存台。上传中断（断线、重发、服务重启、误选文件）
**绝不覆盖**已经确认的数据，封存回执全库**唯一**，进度与回执跨服务重启保留。封存后即使磁盘
静默损坏（位翻转、截断、缺块）仍可**逐块完整性复核**，并能用**完整原文件**只修复异常块，
回执标识与封存时间始终不变。

## 核心规则

- 会话号：`^[A-Za-z0-9]{1,32}$`；文件大小：1 B – 8 MiB。
- 固定块长 `65536` 字节，块从零起算的偏移必须对齐 65536，末块可缩短。
- 每个 `PUT` 携带：块字节、`X-Chunk-Offset`、`X-Total-Size`、`X-Content-SHA256`
  （整文件小写 SHA-256；元数据首次成功写入后，重传可省略后两个头）。
- 分块允许**乱序**到达。
- 元数据（总长度、摘要、块数）在第一个合法分块成功后**永久固定**。
- 相同重传：**幂等 200**；块内容不同或元数据不同：**409 且状态不变**。
- 未对齐、越界、块长错误：**400**，错误信息带具体偏移/长度，且不留任何状态。
- `POST /seal`：无缺块且服务端重算整文件摘要一致时，原子写入唯一回执；
  此后不可新增/更改分块（相同重传仍 200，不同内容 409）。
- 重复封存返回**同一份回执**；缺块返回 409 并列出 `missing_ranges`（闭区间块号）；
  摘要不符返回 409 且不产生回执文件。
- 封存同时持久化**逐块摘要索引** `chunk_index.json`，供封存后逐块复核。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `GET` | `/api/uploads/{session}` | 会话状态：已确认块、缺失范围、回执、索引/修复标志 |
| `PUT` | `/api/uploads/{session}/chunks` | 上传/重传一个分块（头见上）；封存数据永不被此接口改写 |
| `POST` | `/api/uploads/{session}/seal` | 原子封存；已封存则返回原回执 |
| `POST` | `/api/uploads/{session}/audit` | 封存后完整性复核，返回 `HEALTHY` / `DEGRADED` / `REPAIRING` 及异常块范围 |
| `POST` | `/api/uploads/{session}/repair` | 上传完整原文件，仅在长度与回执摘要一致时修复异常块，可断点继续 |

### 完整性复核 `audit`

- **仅对已封存会话开放**：未封存会话返回 409，且**不改变任何上传进度**；未知会话 400。
- 新封存会话（有逐块索引）逐块校验长度与摘要，再独立重算整文件摘要锚定回执。
- 旧会话（无索引）首次复核：先校验**每块长度**与**整文件摘要**；全部成功后**补建可信
  逐块索引**（`index_built: true`）。
- 失败时三类异常**互不重叠、分别给出闭区间块号范围**：
  - `missing_ranges`：块缺失/字节无法读取（**缺块**）；
  - `length_anomaly_ranges`：块长度与元数据不符（**长度异常**）；
  - `digest_mismatch_ranges`：长度正确但摘要不符，并用 `digest_mismatch_located`
    标明是否可定位到具体块；旧会话无索引时只能发现整文件摘要不符，置
    `unlocated_digest_mismatch: true`（**无法定位的摘要不符**）。
- `bad_ranges` 为三类异常的并集；`receipt` 始终回传当前（不变的）回执。
- 修复进行中复核返回 `REPAIRING`、`remaining_ranges` 与 `recovered_ranges`，结果稳定且只读。

### 原文件修复 `repair`

- 请求体为**完整原文件**（`application/octet-stream`）。服务端先验证
  **长度 == 回执 `total_size`** 且 **SHA-256 == 回执摘要**；不一致一律 **400**
  （错误信息带两个长度/摘要），**不写任何块、不留修复状态**，重复提交结果稳定。
- 校验通过后，逐块把与原文件不同的块（缺块、长度异常、摘要不符）原子替换。
  修复计划以**回执摘要为根信任**（直接比对原文件），因此即使逐块索引被篡改也能定位。
- **可中断、可续作、必然收敛**：每替换一块即 fsync 落盘修复进度 `repair/state.json`
  与已验证原文件 `repair/restore.tmp`；替换中断后，**下次请求或服务重启**自动从未完成
  块继续，期间新发生的损坏也会被纳入计划。
- 全部替换完成后必须再次重算整文件摘要与回执一致，才提交并清理修复目录；否则 409 且保留进度。
- **回执与封存时间在整个修复过程中字节不变**；旧会话修复成功后补建可信索引。
- 会话本就健康时重复 `repair` 是幂等空操作（`already_healthy: true`，200）。
- 未封存会话 409；原分块接口在封存后仍只能幂等重放，永远无法借修复之名改写封存数据。

## 持久化与崩溃安全

`./data/<会话>/`：

```
meta.json        # 元数据，首次合法分块时原子写入后不可变
chunks/00000000  # 每块一个文件，写临时文件 + fsync + rename 原子落盘
receipt.json     # 仅封存成功后原子出现；存在即代表已封存（永不被修复改写）
chunk_index.json # 逐块（块号/长度/SHA-256）可信索引：封存成功前原子写入；
                 # 旧会话首次复核/修复成功后补建；修复后与回执锚定的字节对齐
repair/          # 仅修复期间存在，收敛后整体删除：
  state.json     #   可续作计划（异常块、已修复块及异常分类，每块后 fsync）
  restore.tmp    #   已通过长度+摘要校验的完整原文件副本（fsync）
```

所有写操作经进程内锁串行化，落盘均为「临时文件 → fsync → 原子 rename → fsync 目录」，
服务重启/容器重建后直接从该目录重建状态，并自动收尾上一次未完成的修复。

## 前端

页面输入会话号、选择文件后浏览器本地计算整文件 SHA-256（优先 WebCrypto，
HTTP 局域网等非安全上下文自动回退到内置纯 TS 实现），逐块 `PUT` 并显示：

- 已确认分块网格与百分比、缺失范围；
- 每块错误（含定位偏移；409 明确提示数据被拒绝覆盖）；
- **重选原文件**即用原会话号**重发所有块**（服务端去重），断线后如此恢复；
- 「查询/恢复服务器进度」可在页面刷新/重启后拉回服务端权威状态；
- 封存后展示唯一回执，并提供**完整性复核**：HEALTHY/DEGRADED/REPAIRING、三类异常块范围
  （缺块/长度异常/摘要不符，含无法定位提示）与彩色分块网格；
- DEGRADED/REPAIRING 时选择**完整原文件**，浏览器先核对长度与摘要，再提交修复；
  中断会自动重发同一文件续作直到 HEALTHY，回执保持不变。

## 运行（Docker Compose）

```bash
docker compose up -d web          # 打开 http://localhost:8000
HOST_PORT=9000 docker compose up -d web
```

- 宿主机端口：`${HOST_PORT:-8000}:8000`；
- 持久数据：宿主机 `./data` 挂载到容器 `/data`；
- 内置健康检查，`depends_on: service_healthy` 可供编排使用。

## 一次性 verify 服务

在完成代码测试、前端生产构建与对运行中服务的 HTTP 冒烟后**自行退出，以退出码汇报成败**：

```bash
docker compose build verify
docker compose up --exit-code-from verify verify
# 或一行：
docker compose run --rm verify
```

阶段（任一失败立即非零退出）：

1. `pytest`：后端测试（乱序、幂等、409 不改状态、定位拒绝、缺块范围、摘要不符无回执、
   封存后不可变、跨"重启"持久化、边界尺寸；以及逐块索引、旧会话首检补建、缺块/长度异常/
   无法定位摘要不符的区分、错误文件稳定 400、修复收敛与回执不变、中断续作与重启续作、
   篡改索引无法隐藏损坏等）；
2. `npm run build`：`tsc` 类型检查 + Vite 构建；
3. `verify/smoke.py`：对 `http://web:8000` 的纯 stdlib HTTP 全链路冒烟。verify 容器与 web
   共享 `./data` 卷，以便在真实磁盘上翻转/截断/删除已封存块，再走 audit + repair 全流程。

## 本地开发

```bash
# 后端
cd backend && python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DATA_DIR=../data uvicorn app.main:app --reload

# 前端（dev server 代理 /api 与 /health 到 :8000）
cd frontend && npm install && npm run dev
```
