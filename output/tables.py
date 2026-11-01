"""LaTeX table generation — reads results/, writes latex_tables.tex."""

from infra.logger import get_logger
from infra.storage import load_json, save_json
from infra.config import RESULTS_DIR, MEASURED_RUNS, WARMUP_RUNS

logger = get_logger("tables")


def _load(f):
    try:
        return load_json(f)
    except FileNotFoundError:
        return None


def _hline():
    return "\\hline"


def generate_all_tables() -> str:
    lines = []

    def L(s=""):
        lines.append(s)

    # ── Table 1: Operation Latency + Energy ───────────────────────────────
    d = _load("operation_benchmarks.json")
    if d:
        data = d["results"]
        L("% TABLE 1: Operation Latency and Energy")
        L("\\begin{table}[t]\\centering")
        L(f"\\caption{{Mean operation latency (ms) and estimated energy (mJ) on")
        L(f"Raspberry Pi~4B. Values: mean~$\\pm$~std ({MEASURED_RUNS} runs, "
          f"{WARMUP_RUNS} warm-up, CPU at 1800~MHz).}}")
        L("\\label{tab:latency}")
        L("\\begin{tabular}{llrrrr}")
        L(_hline())
        L("Config & Op & Mean (ms) & Std & P95 & Energy (mJ) \\\\")
        L(_hline())
        for cfg, ops in data.items():
            cfg_l = cfg.replace("_", "\\_").replace("+", " $+$ ")
            first = True
            for op in ["keygen", "encap", "exchange", "decap", "sign", "verify"]:
                if op not in ops or "mean_ms" not in ops[op]:
                    continue
                v = ops[op]
                c = cfg_l if first else ""
                first = False
                L(f"{c} & {op} & {v['mean_ms']:.4f} & {v['std_ms']:.4f} & "
                  f"{v['p95_ms']:.4f} & {v.get('energy_mj','--')} \\\\")
            L(_hline())
        L("\\end{tabular}\\end{table}")
        L()

    # ── Table 2: Artifact Sizes ───────────────────────────────────────────
    if d:
        L("% TABLE 2: Artifact Sizes")
        L("\\begin{table}[t]\\centering")
        L("\\caption{Public key, ciphertext, shared secret, and signature sizes (bytes).}")
        L("\\label{tab:sizes}")
        L("\\begin{tabular}{lrrrr}")
        L(_hline())
        L("Config & PK (B) & CT (B) & SS (B) & Sig (B) \\\\")
        L(_hline())
        for cfg, ops in data.items():
            if "sizes" not in ops:
                continue
            s = ops["sizes"]
            cfg_l = cfg.replace("_", "\\_").replace("+", " $+$ ")
            L(f"{cfg_l} & {s.get('kem_pk_bytes','--')} & "
              f"{s.get('kem_ct_bytes','--')} & {s.get('kem_ss_bytes','--')} & "
              f"{s.get('dsa_sig_bytes','--')} \\\\")
        L(_hline())
        L("\\end{tabular}\\end{table}")
        L()

    # ── Table 3: End-to-End Handshake ─────────────────────────────────────
    d = _load("e2e_benchmarks.json")
    if d:
        data = d.get("results", d)
        L("% TABLE 3: End-to-End Handshake")
        L("\\begin{table}[t]\\centering")
        L(f"\\caption{{Post-quantum handshake latency (Steps~1--6) and command "
          f"round-trip ({MEASURED_RUNS} runs, long-term DSA keypair persists "
          f"across sessions).}}")
        L("\\label{tab:e2e}")
        L("\\begin{tabular}{llrrrr}")
        L(_hline())
        L("Config & Phase & Mean (ms) & Std & P95 & Energy (mJ) \\\\")
        L(_hline())
        for key, label in [("ECDH_baseline", "ECDH baseline"),
                            ("ML-KEM-768_proxy", "ML-KEM-768 proxy")]:
            if key not in data:
                continue
            first = True
            for phase, plabel in [
                ("handshake_steps1to6", "Handshake (Steps~1--6)"),
                ("command_encrypt", "Cmd encrypt"),
                ("command_decrypt", "Cmd decrypt"),
            ]:
                if phase not in data[key]:
                    continue
                v = data[key][phase]
                c = label if first else ""
                first = False
                L(f"{c} & {plabel} & {v['mean_ms']:.4f} & {v['std_ms']:.4f} & "
                  f"{v['p95_ms']:.4f} & {v.get('energy_mj','--')} \\\\")
            L(_hline())
        L("\\end{tabular}\\end{table}")
        L()

    # ── Table 4: Network Latency ──────────────────────────────────────────
    d = _load("network_benchmarks.json")
    if d:
        data = d["results"]
        L("% TABLE 4: Network Latency Impact")
        L("\\begin{table}[t]\\centering")
        L(f"\\caption{{ML-KEM-768 handshake latency under simulated network RTT "
          f"({MEASURED_RUNS} runs each, 4 one-way hops simulated).}}")
        L("\\label{tab:network}")
        L("\\begin{tabular}{rrrr}")
        L(_hline())
        L("RTT (ms) & Mean (ms) & P95 (ms) & Energy (mJ) \\\\")
        L(_hline())
        for v in data.values():
            L(f"{v['network_rtt_ms']} & {v['mean_ms']:.3f} & "
              f"{v['p95_ms']:.3f} & {v.get('energy_mj','--')} \\\\")
        L(_hline())
        L("\\end{tabular}\\end{table}")
        L()

    # ── Table 5: Side-Channel (Pass/Fail Tests) ───────────────────────────
    d = _load("sidechannel_analysis.json")
    any_dag = False
    if d:
        L("% TABLE 5: Side-Channel Analysis")
        L("\\begin{table}[t]\\centering")
        L("\\caption{Side-channel analysis results. Memory forensics, MITM "
          "simulation, nonce collision, and TVLA are pass/fail tests against "
          "documented methodologies; the timing/AES-GCM baseline comparison "
          "in Table~\\ref{tab:cvbaseline} is descriptive, not pass/fail.}")
        L("\\label{tab:sidechannel}")
        L("\\begin{tabular}{lll}")
        L(_hline())
        L("Test & Key Result & Status \\\\")
        L(_hline())
        for key, r in d.items():
            if not isinstance(r, dict) or "passed" not in r:
                continue  # excludes timing_baseline_relative (descriptive, no verdict)
            test = r.get("test", key)
            if len(test) > 42:
                test = test[:39] + "..."
            if "t_statistic" in r:
                val = (f"$t={r['t_statistic']:.3f}$ "
                       f"(thresh $\\pm{r['threshold']}$)")
            elif "unique_nonces" in r:
                val = (f"{r['unique_nonces']}/{r['nonces_generated']} unique, "
                       f"$P={r.get('theoretical_probability','--')}$")
            elif "mitm_blocked_by_mldsa" in r:
                val = f"ML-DSA raised {r.get('exception_raised','exception')}"
            elif "key_found_after_end" in r:
                val = "Not found (zeroized)" if not r["key_found_after_end"] else "Found\\dag"
                if r["key_found_after_end"]:
                    any_dag = True
            else:
                val = "--"
            status = "\\checkmark" if r["passed"] else "\\dag"
            if not r["passed"]:
                any_dag = True
            L(f"{test} & {val} & ${status}$ \\\\")
        L(_hline())
        if any_dag:
            L("\\multicolumn{3}{l}{\\dag~See Section~7 for discussion of this result.} \\\\")
        L("\\end{tabular}\\end{table}")
        L()

        # ── Table 5b: Timing/AES-GCM Baseline (Descriptive) ───────────────
        cv = d.get("timing_baseline_relative")
        if cv:
            aes = cv.get("aes_gcm_baseline", {})
            proxy = cv.get("pqc_proxy_decapsulate", {})
            L("% TABLE 5b: Timing CV Relative to AES-256-GCM Baseline")
            L("\\begin{table}[t]\\centering")
            L(f"\\caption{{Timing variability (coefficient of variation) of the "
              f"architecture's decapsulation path relative to an AES-256-GCM "
              f"baseline measured in the same run ({cv.get('n_per_operation','--')} "
              f"samples each). Descriptive noise-floor comparison, not a pass/fail "
              f"test; see Table~\\ref{{tab:sidechannel}} for the TVLA leakage "
              f"assessment on this same path.}}")
            L("\\label{tab:cvbaseline}")
            L("\\begin{tabular}{lrr}")
            L(_hline())
            L("Operation & Mean (ms) & CV (\\%) \\\\")
            L(_hline())
            L(f"AES-256-GCM (baseline) & {aes.get('mean_ms','--')} & {aes.get('cv_pct','--')} \\\\")
            L(f"PQCProxy.decapsulate() & {proxy.get('mean_ms','--')} & {proxy.get('cv_pct','--')} \\\\")
            L(_hline())
            L(f"\\multicolumn{{3}}{{l}}{{Difference: "
              f"{proxy.get('cv_relative_to_baseline_pp','--')} percentage points "
              f"vs.\\ baseline.}} \\\\")
            L("\\end{tabular}\\end{table}")
            L()

    # ── Table 6: ESP32 Infeasibility + Classical Timing ──────────────────
    d = _load("esp32_results.json")
    if d:
        free_kb = d.get("free_heap_bytes", 0) / 1024
        req_kb  = d.get("mlkem768_required_bytes", 921600) / 1024
        aes_ms  = d.get("aes128_mean_ms", None)
        ecdh_ms = d.get("ecdh_keygen_mean_ms", None)
        L("% TABLE 6: ESP32-S3 Memory Infeasibility and Classical Crypto Timing")
        L("\\begin{table}[t]\\centering")
        L("\\caption{ESP32-S3 memory feasibility for ML-KEM-768 and classical "
          "cryptography timing. The device successfully runs AES-128 and ECDH "
          "(classical), but cannot allocate the memory required for ML-KEM-768 "
          "(post-quantum), empirically confirming the device-side infeasibility "
          "claim of the proposed architecture.}")
        L("\\label{tab:esp32}")
        L("\\begin{tabular}{lr}")
        L(_hline())
        L("Metric & Value \\\\")
        L(_hline())
        L("\\multicolumn{2}{l}{\\textit{Hardware}} \\\\")
        L(_hline())
        L(f"Platform & {d.get('platform','ESP32-S3')} \\\\")
        L(f"CPU frequency & {d.get('cpu_mhz','--')}~MHz \\\\")
        L(f"Total SRAM & {d.get('sram_bytes','--')}~bytes \\\\")
        L(f"Free heap (runtime) & {d.get('free_heap_bytes','--')}~bytes ({free_kb:.0f}~KB) \\\\")
        L(_hline())
        L("\\multicolumn{2}{l}{\\textit{Classical Cryptography (device capable)} } \\\\")
        L(_hline())
        if aes_ms:
            L(f"AES-128 encrypt & {aes_ms:.4f}~ms \\\\")
        if ecdh_ms:
            L(f"ECDH-P256 keygen & {ecdh_ms:.4f}~ms \\\\")
        L(_hline())
        L("\\multicolumn{2}{l}{\\textit{Post-Quantum Cryptography (device incapable)} } \\\\")
        L(_hline())
        L(f"ML-KEM-768 memory required & {d.get('mlkem768_required_bytes',921600)}~bytes ({req_kb:.0f}~KB) \\\\")
        L(f"malloc(900~KB) result & {'Succeeded' if d.get('malloc_900kb_succeeded') else '\\textbf{FAILED}'} \\\\")
        L(f"ML-KEM-768 feasible & {'Yes' if d.get('mlkem768_feasible') else '\\textbf{No}'} \\\\")
        L(_hline())
        L("\\end{tabular}\\end{table}")
        L()

    # ── Table 7 & 8: Stress Test ───────────────────────────────────────────
    d = _load("stress_benchmarks.json")
    if d:
        data = d["results"]
        concurrent = data.get("concurrent", {})
        throughput = data.get("throughput", {})
        extrap = data.get("extrapolation", {})

        if concurrent:
            L("% TABLE 7: Stress Test — Concurrent Sessions")
            L("\\begin{table}[t]\\centering")
            L("\\caption{ML-KEM-768 proxy performance under concurrent load "
              "(Raspberry Pi~4B).}")
            L("\\label{tab:stress}")
            L("\\begin{tabular}{rrrrr}")
            L(_hline())
            L("Threads & Success (\\%) & Mean lat. (ms) & Max lat. (ms) & Sessions/s \\\\")
            L(_hline())
            for v in concurrent.values():
                L(f"{v['threads']} & {v['success_rate_pct']} & "
                  f"{v['mean_latency_ms']:.2f} & {v['max_latency_ms']:.2f} & "
                  f"{v['throughput_per_sec']:.1f} \\\\")
            L(_hline())
            if throughput:
                mem = throughput.get("memory", {})
                L(f"\\multicolumn{{5}}{{l}}{{Sequential throughput: "
                  f"{throughput.get('sessions_per_second','--')} sessions/s over "
                  f"{throughput.get('sessions','--')} sessions. "
                  f"Memory growth: {mem.get('growth_kb','--')}~KB "
                  f"({'leak detected' if mem.get('leak_detected') else 'no leak'}).}} \\\\")
            L("\\end{tabular}\\end{table}")
            L()

        if extrap:
            L("% TABLE 8: Cloud Throughput Extrapolation")
            L("\\begin{table}[t]\\centering")
            L("\\caption{Extrapolated ML-KEM-768 proxy throughput for deployment "
              "scenarios. Based on measured Pi~4B performance, assuming linear "
              "per-core scaling.}")
            L("\\label{tab:extrapolation}")
            L("\\begin{tabular}{lr}")
            L(_hline())
            L("Deployment Scenario & Sessions / Second \\\\")
            L(_hline())
            L(f"Raspberry Pi~4B (1 core) & {extrap.get('pi4b_single_core_sps','--')} \\\\")
            L(f"Raspberry Pi~4B (4 cores) & {extrap.get('pi4b_all_cores_sps','--')} \\\\")
            L(f"Cloud instance (8 cores) & {extrap.get('cloud_8core_instance_sps','--')} \\\\")
            L(f"Cloud instance (32 cores) & {extrap.get('cloud_32core_instance_sps','--')} \\\\")
            L(_hline())
            L("\\multicolumn{2}{l}{Linear scaling assumed. Actual cloud throughput "
              "depends on network I/O and load balancing.} \\\\")
            L("\\end{tabular}\\end{table}")
            L()

    out = "\n".join(lines)
    out_path = RESULTS_DIR / "latex_tables.tex"
    with open(out_path, "w") as f:
        f.write(out)
    logger.info(f"All tables saved to: {out_path}")
    return out
