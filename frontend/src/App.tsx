import { useCallback, useMemo, useState } from "react";
import {
  ApiError,
  AuditResult,
  CHUNK_SIZE,
  MAX_FILE_SIZE,
  MIN_FILE_SIZE,
  SESSION_RE,
  ChunkAck,
  Receipt,
  SessionStatus,
  auditSession,
  fetchStatus,
  putChunk,
  repairSession,
  seal,
  sha256Hex,
} from "./api";
import "./styles.css";

interface ChunkError {
  index: number;
  offset: number;
  status: number;
  message: string;
}

type Range = [number, number];

function formatRanges(ranges: Range[]): string {
  if (ranges.length === 0) return "无";
  return ranges
    .map(([a, b]) => {
      if (a === b) return `#${a}（偏移 ${a * CHUNK_SIZE}）`;
      return `#${a}–#${b}（偏移 ${a * CHUNK_SIZE}–${(b + 1) * CHUNK_SIZE - 1}）`;
    })
    .join("，");
}

function rangeSet(ranges: Range[], count: number): Set<number> {
  const out = new Set<number>();
  for (const [a, b] of ranges) {
    for (let i = a; i <= Math.min(b, count - 1); i++) out.add(i);
  }
  return out;
}

export default function App() {
  const [session, setSession] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [digest, setDigest] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState<Set<number>>(new Set());
  const [chunkCount, setChunkCount] = useState<number>(0);
  const [totalSize, setTotalSize] = useState<number>(0);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<string>("");
  const [errors, setErrors] = useState<ChunkError[]>([]);
  const [receipt, setReceipt] = useState<Receipt | null>(null);
  const [sealed, setSealed] = useState(false);
  const [notice, setNotice] = useState<string>("");
  const [audit, setAudit] = useState<AuditResult | null>(null);
  const [auditError, setAuditError] = useState<string>("");
  const [repairFile, setRepairFile] = useState<File | null>(null);
  const [repairDigest, setRepairDigest] = useState<string | null>(null);
  const [repairPhase, setRepairPhase] = useState<string>("");

  const sessionValid = SESSION_RE.test(session);
  const fileError = useMemo(() => {
    if (!file) return "";
    if (file.size < MIN_FILE_SIZE) return "文件不得小于 1 字节";
    if (file.size > MAX_FILE_SIZE) return "文件不得超过 8 MiB";
    return "";
  }, [file]);

  const repairFileHint = useMemo(() => {
    if (!repairFile) return "";
    if (!receipt) return "";
    if (repairFile.size !== receipt.total_size) {
      return `文件长度 ${repairFile.size} 与回执总长度 ${receipt.total_size} 不一致，服务器将拒绝修复。`;
    }
    if (repairDigest && repairDigest !== receipt.sha256) {
      return "整文件 SHA-256 与回执摘要不一致，服务器将拒绝修复（请确认选择的是原文件）。";
    }
    if (repairDigest === receipt.sha256) {
      return "长度与 SHA-256 均与回执一致，可以提交修复。";
    }
    return "";
  }, [repairFile, repairDigest, receipt]);

  const expectedChunks = file
    ? Math.floor((file.size + CHUNK_SIZE - 1) / CHUNK_SIZE)
    : 0;

  const resetProgress = useCallback(() => {
    setConfirmed(new Set());
    setErrors([]);
    setReceipt(null);
    setSealed(false);
    setNotice("");
    setChunkCount(0);
    setTotalSize(0);
    setAudit(null);
    setAuditError("");
    setRepairFile(null);
    setRepairDigest(null);
    setRepairPhase("");
  }, []);

  const onPickFile = useCallback(
    async (picked: File | null) => {
      setFile(picked);
      setDigest(null);
      resetProgress();
      if (!picked) return;
      if (picked.size < MIN_FILE_SIZE || picked.size > MAX_FILE_SIZE) return;
      setPhase("正在计算整文件 SHA-256…");
      const buffer = await picked.arrayBuffer();
      setDigest(await sha256Hex(buffer));
      setChunkCount(Math.floor((picked.size + CHUNK_SIZE - 1) / CHUNK_SIZE));
      setTotalSize(picked.size);
      setPhase("");
    },
    [resetProgress]
  );

  const onPickRepairFile = useCallback(async (picked: File | null) => {
    setRepairFile(picked);
    setRepairDigest(null);
    setRepairPhase("");
    if (!picked) return;
    setRepairPhase("正在计算原文件 SHA-256…");
    const buffer = await picked.arrayBuffer();
    setRepairDigest(await sha256Hex(buffer));
    setRepairPhase("");
  }, []);

  // Merge a server ack. The server's confirmed list is authoritative.
  const applyAck = useCallback((ack: ChunkAck) => {
    setConfirmed(new Set(ack.confirmed_chunks));
    setChunkCount(ack.chunk_count);
    setSealed(ack.sealed);
  }, []);

  const sendAllChunks = useCallback(async (): Promise<boolean> => {
    if (!file || !digest) return false;
    const buffer = await file.arrayBuffer();
    const total = buffer.byteLength;
    const count = Math.floor((total + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // Resend EVERY chunk (the server deduplicates identical retransmissions).
    // This is how an interrupted transfer is recovered with the same session.
    for (let i = 0; i < count; i++) {
      const offset = i * CHUNK_SIZE;
      const part = buffer.slice(offset, Math.min(offset + CHUNK_SIZE, total));
      setPhase(`正在发送分块 ${i + 1} / ${count}`);
      try {
        const ack = await putChunk(session, offset, part, total, digest);
        applyAck(ack);
        setErrors((prev) => prev.filter((e) => e.index !== i));
      } catch (e) {
        const err = e as ApiError;
        setErrors((prev) => [
          ...prev.filter((x) => x.index !== i),
          {
            index: i,
            offset,
            status: err.status ?? 0,
            message:
              err.status === 409
                ? `409 冲突：该会话已确认不同内容，服务器拒绝覆盖（${err.message}）`
                : err.status === 0
                  ? `网络错误（可能断线），已确认分块保留在服务器，可重发恢复：${err.message}`
                  : err.message,
          },
        ]);
        if (err.status === 409) {
          // A conflict means a different file is bound to this session:
          // stop immediately, never overwrite, do not attempt to seal.
          setPhase("传输因 409 冲突中止，已确认数据未被修改。");
          return false;
        }
        // Network/5xx error: keep everything confirmed so far; stop.
        setPhase("传输中断，已确认分块未丢失；重选同一文件并重发即可恢复。");
        return false;
      }
    }
    return true;
  }, [applyAck, digest, file, session]);

  const runAudit = useCallback(async (): Promise<AuditResult | null> => {
    try {
      const result = await auditSession(session);
      setAudit(result);
      setAuditError("");
      setReceipt(result.receipt);
      setSealed(true);
      setChunkCount(result.chunk_count);
      // A sealed session has every block; paint the grid even when the
      // operator went straight to audit without a status refresh.
      setConfirmed(new Set(Array.from({ length: result.chunk_count }, (_, i) => i)));
      return result;
    } catch (e) {
      const err = e as ApiError;
      setAudit(null);
      if (err.status === 409) {
        setAuditError("该会话尚未封存：完整性复核仅对已封存会话开放，上传进度不会被改变。");
      } else if (err.status === 404) {
        setAuditError("服务器上没有该会话。");
      } else {
        setAuditError(`复核失败：${err.message}`);
      }
      return null;
    }
  }, [session]);

  const handleUploadAndSeal = useCallback(async () => {
    setBusy(true);
    setErrors([]);
    setNotice("");
    try {
      const complete = await sendAllChunks();
      if (!complete) return;
      setPhase("所有分块已确认，正在请求封存…");
      const result = await seal(session);
      if (result.receipt) {
        setReceipt(result.receipt);
        setSealed(true);
        setNotice("封存成功，回执已生成并持久化。正在做首次完整性复核…");
        setPhase("");
        await runAudit();
      } else if (result.missingRanges) {
        setNotice(`仍有缺块，未生成回执：${formatRanges(result.missingRanges)}`);
        setPhase("");
      } else {
        setNotice(`封存被拒绝，未生成回执：${result.error ?? "摘要不一致"}`);
        setPhase("");
      }
    } finally {
      setBusy(false);
    }
  }, [runAudit, sendAllChunks, session]);

  const handleSealOnly = useCallback(async () => {
    setBusy(true);
    try {
      const result = await seal(session);
      if (result.receipt) {
        setReceipt(result.receipt);
        setSealed(true);
        setNotice("封存成功。");
        await runAudit();
      } else if (result.missingRanges) {
        setNotice(`仍有缺块：${formatRanges(result.missingRanges)}`);
      } else {
        setNotice(`封存失败：${result.error}`);
      }
    } finally {
      setBusy(false);
    }
  }, [runAudit, session]);

  const handleAudit = useCallback(async () => {
    if (!sessionValid) return;
    setBusy(true);
    try {
      await runAudit();
    } finally {
      setBusy(false);
    }
  }, [runAudit, sessionValid]);

  const handleRepair = useCallback(async () => {
    if (!repairFile || !repairDigest) return;
    setBusy(true);
    setAuditError("");
    setNotice("");
    try {
      const buffer = await repairFile.arrayBuffer();
      setRepairPhase("正在提交原文件，服务端先校验长度与回执摘要…");
      let result = await repairSession(session, buffer);
      setAudit(result);
      // If a previous replacement was interrupted (network drop, restart),
      // the same request resumes exactly where it stopped and converges.
      let guard = 0;
      while (result.status === "REPAIRING" && guard < 100000) {
        setRepairPhase(
          `修复进行中（断点继续），剩余异常块：${formatRanges(result.remaining_ranges)}`,
        );
        result = await repairSession(session, buffer);
        setAudit(result);
        guard += 1;
      }
      if (result.status === "HEALTHY") {
        setReceipt(result.receipt);
        setNotice(
          result.already_healthy
            ? "会话本就健康：重复修复未改动任何数据，回执不变。"
            : "异常块已全部修复并复核通过；回执标识与封存时间保持不变。",
        );
        setRepairPhase("");
      }
    } catch (e) {
      const err = e as ApiError;
      if (err.status === 400) {
        setAuditError(`修复被拒绝，任何分块均未改动：${err.message}`);
      } else if (err.status === 409) {
        setAuditError(`修复未能收敛或会话未封存：${err.message}`);
      } else {
        setAuditError(`修复请求出错，已落盘的修复进度会在下次请求时继续：${err.message}`);
      }
      setRepairPhase("");
    } finally {
      setBusy(false);
    }
  }, [repairDigest, repairFile, session]);

  const handleRefresh = useCallback(async () => {
    if (!sessionValid) return;
    setBusy(true);
    try {
      const status: SessionStatus | null = await fetchStatus(session);
      if (!status) {
        resetProgress();
        setNotice("服务器上没有该会话（可能从未成功写入分块）。");
        return;
      }
      setChunkCount(status.chunk_count);
      setTotalSize(status.total_size);
      setConfirmed(new Set(status.confirmed_chunks));
      setSealed(status.sealed);
      setReceipt(status.receipt);
      setAudit(null);
      setAuditError("");
      setNotice(
        status.sealed
          ? "该会话已封存，回执如下（服务重启后仍然保留）。可点击「完整性复核」确认字节可读。"
          : `已从服务器恢复进度：${status.confirmed_chunks.length}/${status.chunk_count} 块。`,
      );
    } catch (e) {
      setNotice(`查询失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }, [resetProgress, session, sessionValid]);

  const pct = chunkCount ? Math.round((confirmed.size / chunkCount) * 100) : 0;
  const ready = sessionValid && !!file && !fileError && !!digest && !busy;

  const badChunks = audit
    ? rangeSet(
        [
          ...audit.missing_ranges,
          ...audit.length_anomaly_ranges,
          ...audit.digest_mismatch_ranges,
        ],
        audit.chunk_count,
      )
    : new Set<number>();
  const recoveredChunks = audit ? rangeSet(audit.recovered_ranges, audit.chunk_count) : new Set<number>();
  const remainingChunks = audit ? rangeSet(audit.remaining_ranges, audit.chunk_count) : new Set<number>();

  return (
    <main className="page">
      <h1>冷冻电镜采集包 · 断点续传封存台</h1>
      <p className="sub">
        固定分块 65536 字节 · 文件 1 B – 8 MiB · 会话号 1–32 位字母或数字 ·
        已确认分块与封存回执跨重启保留 · 封存后可逐块完整性复核并用原文件修复
      </p>

      <section className="card">
        <label className="field">
          <span>会话号</span>
          <input
            value={session}
            placeholder="例如 CRYO2026A1（1–32 位字母或数字）"
            onChange={(e) => setSession(e.target.value.trim())}
            disabled={busy}
          />
          {session && !sessionValid && (
            <em className="bad">会话号只能包含英文字母与数字，长度 1–32</em>
          )}
        </label>

        <div className="row">
          <button onClick={handleRefresh} disabled={!sessionValid || busy}>
            查询/恢复服务器进度
          </button>
          <button onClick={handleSealOnly} disabled={!sessionValid || busy}>
            仅请求封存
          </button>
          <button onClick={handleAudit} disabled={!sessionValid || busy}>
            完整性复核
          </button>
        </div>

        <label className="field">
          <span>选择采集包文件（重选原文件即可用原会话号重发所有块）</span>
          <input
            type="file"
            // Reset so picking the SAME file again still fires onChange
            // (that is exactly the "reselect the original file" recovery path).
            onClick={(e) => {
              e.currentTarget.value = "";
            }}
            onChange={(e) => void onPickFile(e.target.files?.[0] ?? null)}
            disabled={busy}
          />
          {fileError && <em className="bad">{fileError}</em>}
        </label>

        {file && !fileError && (
          <div className="meta">
            <div>文件名：{file.name}</div>
            <div>
              大小：{file.size} 字节（{expectedChunks} 块）
            </div>
            <div className="digest">
              整文件 SHA-256：{digest ?? "计算中…"}
            </div>
          </div>
        )}

        <div className="row">
          <button
            className="primary"
            onClick={() => void handleUploadAndSeal()}
            disabled={!ready}
          >
            {confirmed.size > 0 ? "重发所有分块并封存" : "传输并封存"}
          </button>
        </div>
      </section>

      <section className="card">
        <h2>进度</h2>
        <div className="bar">
          <div className="bar-fill" style={{ width: `${pct}%` }} />
        </div>
        <div className="status">
          {phase && <div>{phase}</div>}
          已确认分块：{confirmed.size} / {chunkCount || "—"}（{pct}%）
          {totalSize > 0 && ` · 总长度 ${totalSize} 字节`}
          {sealed && <strong className="good"> · 已封存</strong>}
        </div>
        {chunkCount > 0 && (
          <ChunkGrid
            count={chunkCount}
            confirmed={confirmed}
            bad={badChunks}
            recovered={recoveredChunks}
            remaining={remainingChunks}
          />
        )}
        {notice && <div className="notice">{notice}</div>}
      </section>

      {sealed && (
        <AuditCard
          audit={audit}
          auditError={auditError}
          receipt={receipt}
          busy={busy}
          repairFile={repairFile}
          repairDigest={repairDigest}
          repairPhase={repairPhase}
          repairFileHint={repairFileHint}
          onAudit={() => void handleAudit()}
          onPickRepairFile={(f) => void onPickRepairFile(f)}
          onRepair={() => void handleRepair()}
        />
      )}

      {errors.length > 0 && (
        <section className="card">
          <h2>错误（{errors.length}）</h2>
          <ul className="errors">
            {errors.map((e) => (
              <li key={e.index}>
                分块 #{e.index}，偏移 {e.offset}：{e.message}
              </li>
            ))}
          </ul>
        </section>
      )}

      {receipt && (
        <section className="card receipt">
          <h2>封存回执（唯一，重复封存/修复均返回同一份）</h2>
          <dl>
            <dt>回执标识</dt>
            <dd>{receipt.receipt_id}</dd>
            <dt>会话号</dt>
            <dd>{receipt.session}</dd>
            <dt>总长度</dt>
            <dd>{receipt.total_size} 字节</dd>
            <dt>分块数</dt>
            <dd>{receipt.chunks}</dd>
            <dt>SHA-256</dt>
            <dd>{receipt.sha256}</dd>
            <dt>封存时间 (UTC)</dt>
            <dd>{receipt.sealed_at}</dd>
          </dl>
        </section>
      )}
    </main>
  );
}

function AuditCard({
  audit,
  auditError,
  receipt,
  busy,
  repairFile,
  repairDigest,
  repairPhase,
  repairFileHint,
  onAudit,
  onPickRepairFile,
  onRepair,
}: {
  audit: AuditResult | null;
  auditError: string;
  receipt: Receipt | null;
  busy: boolean;
  repairFile: File | null;
  repairDigest: string | null;
  repairPhase: string;
  repairFileHint: string;
  onAudit: () => void;
  onPickRepairFile: (f: File | null) => void;
  onRepair: () => void;
}) {
  const healthy = audit?.status === "HEALTHY";
  const degraded = audit?.status === "DEGRADED";
  const repairing = audit?.status === "REPAIRING";
  const repairReady =
    !!repairFile &&
    !!repairDigest &&
    !!receipt &&
    repairFile.size === receipt.total_size &&
    repairDigest === receipt.sha256 &&
    !busy;

  return (
    <section className="card audit">
      <h2>封存后完整性复核与原文件修复</h2>
      <p className="hint">
        复核只读取已封存字节并与回执（长度、整文件 SHA-256、逐块摘要）比对，
        不改变上传进度；新封存会话自动带可信逐块索引，旧会话首次复核通过后会补建索引。
      </p>
      <div className="row">
        <button className="primary" onClick={onAudit} disabled={busy}>
          {audit ? "重新复核" : "开始完整性复核"}
        </button>
      </div>

      {auditError && <div className="notice bad-notice">{auditError}</div>}

      {audit && (
        <div className="audit-body">
          <div className={`audit-status ${audit.status.toLowerCase()}`}>
            复核结论：{audit.status}
            {audit.status === "HEALTHY" && " — 回执所指字节全部可读且摘要一致"}
            {audit.status === "DEGRADED" && " — 封存数据存在异常，见下列块范围"}
            {audit.status === "REPAIRING" && " — 修复进行中，可继续提交原文件收敛"}
          </div>
          <ul className="audit-lines">
            <li>
              可信逐块索引：
              {audit.index_present ? "已存在" : "缺失（旧会话，按块长度＋整文件摘要复核）"}
              {audit.index_built && " · 本次首次复核通过，已补建索引"}
            </li>
            <li>缺块（字节无法读取）：{formatRanges(audit.missing_ranges)}</li>
            <li>块长度异常：{formatRanges(audit.length_anomaly_ranges)}</li>
            <li>
              摘要不符块（已定位）：{formatRanges(audit.digest_mismatch_ranges)}
            </li>
            {audit.unlocated_digest_mismatch && (
              <li className="bad">
                整文件摘要与回执不符且无法定位到具体块：请提交完整原文件，服务端将逐块比对定位后修复。
              </li>
            )}
            {repairing && (
              <>
                <li>剩余异常块：{formatRanges(audit.remaining_ranges)}</li>
                <li>本次已恢复块：{formatRanges(audit.recovered_ranges)}</li>
              </>
            )}
            <li>全部异常块范围：{formatRanges(audit.bad_ranges)}</li>
          </ul>

          {(degraded || repairing || healthy) && (
            <div className="repair-box">
              <label className="field">
                <span>提交完整原文件以修复异常块（长度与回执摘要一致才会写入）</span>
                <input
                  type="file"
                  onClick={(e) => {
                    e.currentTarget.value = "";
                  }}
                  onChange={(e) => onPickRepairFile(e.target.files?.[0] ?? null)}
                  disabled={busy}
                />
                {repairFile && (
                  <div className="meta">
                    <div>文件名：{repairFile.name}</div>
                    <div>大小：{repairFile.size} 字节</div>
                    <div className="digest">
                      SHA-256：{repairDigest ?? "计算中…"}
                    </div>
                  </div>
                )}
                {repairFileHint && (
                  <em className={repairReady ? "good" : "bad"}>{repairFileHint}</em>
                )}
              </label>
              {repairPhase && <div className="status">{repairPhase}</div>}
              <div className="row">
                <button onClick={onRepair} disabled={!repairReady}>
                  {repairing ? "继续并收敛修复" : healthy ? "重复修复（幂等）" : "上传原文件并修复"}
                </button>
              </div>
              <p className="hint">
                修复逐块替换并在每块后持久化进度；若替换中断，下次请求或服务重启会从未完成块继续。
                回执标识与封存时间在修复前后始终不变，原分块接口也不会改写封存数据。
              </p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

function ChunkGrid({
  count,
  confirmed,
  bad,
  recovered,
  remaining,
}: {
  count: number;
  confirmed: Set<number>;
  bad: Set<number>;
  recovered: Set<number>;
  remaining: Set<number>;
}) {
  const cells = Array.from({ length: count }, (_, i) => i);
  return (
    <div className="grid" title={`共 ${count} 块，绿色为已确认，红色为复核异常`}>
      {cells.map((i) => {
        const cls = remaining.has(i)
          ? "cell remaining"
          : bad.has(i)
            ? "cell bad"
            : recovered.has(i)
              ? "cell recovered"
              : confirmed.has(i)
                ? "cell on"
                : "cell";
        return (
          <span key={i} className={cls}>
            {i}
          </span>
        );
      })}
    </div>
  );
}
