import { useCallback, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";

const gb = (b) => (b / 1073741824).toFixed(1);
const Spark = ({ data, max = 100 }) => (
  <svg viewBox="0 0 120 36" className="spark" preserveAspectRatio="none">
    <polyline fill="none" points={data.map((v, i) => `${(i / 59) * 120},${36 - (v / max) * 34}`).join(" ")} />
  </svg>
);

export default function App() {
  const [tab, setTab] = useState("alerts");
  const [rt, setRt] = useState(false);
  const [cpu, setCpu] = useState([]); const [ram, setRam] = useState([]); const [mem, setMem] = useState({ used: 0, total: 1 });
  const [report, setReport] = useState(null); const [busy, setBusy] = useState(false);
  const [vault, setVault] = useState([]); const [log, setLog] = useState([]);
  const [err, setErr] = useState("");

  const refresh = useCallback(() => invoke("list_quarantine").then(setVault).catch((e) => setErr(String(e))), []);
  useEffect(() => {
    refresh();
    const t = setInterval(async () => {
      const s = await invoke("system_stats");
      setCpu((h) => [...h, s.cpu].slice(-60)); setRam((h) => [...h, (s.ram_used / s.ram_total) * 100].slice(-60));
      setMem({ used: s.ram_used, total: s.ram_total });
    }, 1000);
    const un = listen("threat", (e) => { setLog((l) => [e.payload, ...l].slice(0, 50)); refresh(); });
    return () => { clearInterval(t); un.then((f) => f()); };
  }, [refresh]);

  const toggle = async () => { try { setRt(await invoke("set_realtime", { enabled: !rt })); } catch (e) { setErr(String(e)); } };
  const scan = async () => {
    const path = await open({ directory: true }); if (!path) return;
    setBusy(true); setErr("");
    try { setReport(await invoke("scan", { path, autoQuarantine: true })); await refresh(); }
    catch (e) { setErr(String(e)); } finally { setBusy(false); }
  };
  const act = (cmd, id) => invoke(cmd, { id }).then(refresh).catch((e) => setErr(String(e)));

  const threat = Math.max(0, ...(report?.findings.map((f) => f.score) ?? []), ...log.map((l) => l.score));
  const C = 2 * Math.PI * 90;
  const alerts = [...log, ...(report?.findings ?? [])];

  return (
    <div className="shell">
      <header><b>AEGIS</b> CYBER DEFENSE<span className={rt ? "pill ok" : "pill"}>{rt ? "protected" : "protection off"}</span></header>
      <main>
        <section className="panel left">
          <h3>Real-time protection</h3>
          <button className={"switch " + (rt ? "on" : "")} onClick={toggle}>{rt ? "ACTIVE" : "OFF"}</button>
          <p className="dim">{report ? `Last scan: ${report.scanned} files in ${report.ms} ms` : "No scan yet"}</p>
          <h3>CPU <em>{(cpu.at(-1) ?? 0).toFixed(0)}%</em></h3><Spark data={cpu} />
          <h3>RAM <em>{gb(mem.used)} / {gb(mem.total)} GB</em></h3><Spark data={ram} />
          <button className="primary" disabled={busy} onClick={scan}>{busy ? "Scanning…" : "Scan a folder"}</button>
          {err && <p className="err">{err}</p>}
        </section>
        <section className="gauge">
          <svg viewBox="0 0 220 220">
            <circle cx="110" cy="110" r="90" className="track" />
            <circle cx="110" cy="110" r="90" className={threat >= 70 ? "arc bad" : threat >= 40 ? "arc warn" : "arc"}
              strokeDasharray={`${(threat / 100) * C * 0.75} ${C}`} transform="rotate(135 110 110)" />
          </svg>
          <div className="read"><small>{threat >= 70 ? "Critical threat" : threat >= 40 ? "Suspicious" : "No active threat"}</small><b>{threat}%</b></div>
        </section>
        <section className="panel right">
          <h3>Quarantine vault <em>{vault.length} files</em></h3>
          <p className="dim">Encrypted with AES-256-GCM</p>
        </section>
      </main>
      <nav>{["alerts", "vault"].map((t) => <button key={t} className={tab === t ? "act" : ""} onClick={() => setTab(t)}>{t}</button>)}</nav>
      <div className="drawer">
        {tab === "alerts" && (alerts.length ? alerts.map((f, i) => (
          <div className="row" key={i}><span className={"tag " + f.verdict}>{f.verdict}</span><code>{f.path}</code><span>{f.reasons.join(", ")}</span><b>{f.score}</b></div>
        )) : <p className="dim">No alerts. Turn on protection or scan a folder.</p>)}
        {tab === "vault" && (vault.length ? vault.map((e) => (
          <div className="row" key={e.id}><code>{e.orig_path}</code><code>{e.sha256.slice(0, 16)}…</code><span>{new Date(e.time * 1000).toLocaleString()}</span>
            <button onClick={() => act("restore", e.id)}>Restore</button><button onClick={() => act("delete_item", e.id)}>Delete</button></div>
        )) : <p className="dim">The vault is empty.</p>)}
      </div>
    </div>
  );
}
