"""All plot generation — reads from results/, writes to plots/."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from infra.logger import get_logger
from infra.storage import load_json
from infra.config import (PLOTS_DIR, PLOT_COLORS, PLOT_DPI, STRESS_SESSIONS_TOTAL,
                           MEASURED_RUNS, CPU_POWER_W, CPU_FREQ_REF_MHZ)

logger = get_logger("plots")

plt.rcParams.update({
    "font.size": 11, "font.family": "serif",
    "figure.dpi": PLOT_DPI, "axes.grid": True, "grid.alpha": 0.3,
})


def _save(name: str):
    path = PLOTS_DIR / name
    plt.savefig(path, dpi=PLOT_DPI, bbox_inches="tight")
    plt.close()
    logger.info(f"  \u2714 {name}")


def plot_latency_comparison():
    data     = load_json("operation_benchmarks.json")["results"]
    configs  = list(data.keys())
    norm_ops = ["keygen", "encap", "decap", "sign", "verify"]
    norm_lbl = ["KeyGen", "Encap/Exch", "Decap", "Sign", "Verify"]
    x     = np.arange(len(norm_ops))
    width = 0.2
    fig, ax = plt.subplots(figsize=(11, 5))
    for i, (cfg, color) in enumerate(zip(configs, PLOT_COLORS)):
        means, stds = [], []
        for op in norm_ops:
            actual = "exchange" if op == "encap" and "exchange" in data[cfg] else op
            v = data[cfg].get(actual, {})
            means.append(v.get("mean_ms", 0))
            stds.append(v.get("std_ms", 0))
        offset = (i - len(configs) / 2 + 0.5) * width
        ax.bar(x + offset, means, width, yerr=stds, capsize=3,
               label=cfg.split("+")[0], color=color, alpha=0.85)
    ax.set_xlabel("Operation"); ax.set_ylabel("Mean Latency (ms)")
    ax.set_title(f"PQC vs Classical Operation Latency \u2014 Raspberry Pi 4B ({MEASURED_RUNS} runs)")
    ax.set_xticks(x); ax.set_xticklabels(norm_lbl); ax.legend()
    plt.tight_layout(); _save("latency_comparison.png")


def plot_energy_comparison():
    data    = load_json("operation_benchmarks.json")["results"]
    configs = list(data.keys())
    ops     = ["keygen", "encap", "decap", "sign", "verify"]
    labels  = ["KeyGen", "Encap/Exch", "Decap", "Sign", "Verify"]
    x       = np.arange(len(ops))
    width   = 0.2
    fig, ax = plt.subplots(figsize=(11, 5))
    for i, (cfg, color) in enumerate(zip(configs, PLOT_COLORS)):
        energies = []
        for op in ops:
            actual = "exchange" if op == "encap" and "exchange" in data[cfg] else op
            energies.append(data[cfg].get(actual, {}).get("energy_mj", 0))
        offset = (i - len(configs) / 2 + 0.5) * width
        ax.bar(x + offset, energies, width, label=cfg.split("+")[0],
               color=color, alpha=0.85)
    ax.set_xlabel("Operation"); ax.set_ylabel("Estimated Energy (mJ)")
    # CPU_POWER_W/CPU_FREQ_REF_MHZ pulled from config so this label can never
    # drift out of sync with the actual energy model again.
    ax.set_title(f"Estimated Energy per Operation \u2014 Raspberry Pi 4B\n"
                 f"(Cortex-A72 {CPU_POWER_W}W model @ {CPU_FREQ_REF_MHZ}MHz)")
    ax.set_xticks(x); ax.set_xticklabels(labels); ax.legend()
    plt.tight_layout(); _save("energy_comparison.png")


def plot_handshake_comparison():
    data    = load_json("e2e_benchmarks.json")["results"]
    configs = ["ECDH_baseline", "ML-KEM-768_proxy"]
    labels  = ["ECDH (classical)", "ML-KEM-768\n(PQC proxy)"]
    means   = [data[c]["handshake_steps1to6"]["mean_ms"] for c in configs if c in data]
    stds    = [data[c]["handshake_steps1to6"]["std_ms"]  for c in configs if c in data]
    fig, ax = plt.subplots(figsize=(6, 4))
    bars = ax.bar(labels[:len(means)], means, yerr=stds, capsize=5,
                  color=[PLOT_COLORS[0], PLOT_COLORS[2]], alpha=0.85)
    for bar, m in zip(bars, means):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                f"{m:.2f} ms", ha="center", va="bottom", fontsize=10)
    ax.set_ylabel("Mean Latency (ms)")
    ax.set_title(f"Post-Quantum Handshake Latency \u2014 Steps 1\u20136 ({MEASURED_RUNS} runs)")
    plt.tight_layout(); _save("handshake_comparison.png")


def plot_network_impact():
    data  = load_json("network_benchmarks.json")["results"]
    rtts  = [v["network_rtt_ms"] for v in data.values()]
    means = [v["mean_ms"]        for v in data.values()]
    p95s  = [v["p95_ms"]         for v in data.values()]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(rtts, means, "o-", color=PLOT_COLORS[2], label="Mean latency")
    ax.plot(rtts, p95s,  "s--", color=PLOT_COLORS[3], label="95th percentile")
    ax.set_xlabel("Simulated Network RTT (ms)"); ax.set_ylabel("Total Handshake Time (ms)")
    ax.set_title("Handshake Latency vs Network RTT \u2014 ML-KEM-768"); ax.legend()
    plt.tight_layout(); _save("network_impact.png")


def plot_sidechannel_timing():
    """
    Rewritten for the final side-channel test structure. The old version
    read data["timing_attack_simulation"], a test that no longer exists
    (removed — redundant with TVLA, see sidechannel.py notes). This now
    plots the two tests that actually exist for timing: the TVLA
    fixed-vs-random comparison, and the CV%-vs-AES-GCM-baseline comparison.
    """
    data = load_json("sidechannel_analysis.json")

    tvla = data.get("tvla_fixed_random")
    cv   = data.get("timing_baseline_relative")

    if not tvla and not cv:
        logger.warning("No timing side-channel data found — skipping sidechannel_timing.png")
        return

    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))

    # --- Left: TVLA fixed vs random mean timing ---
    ax1 = axes[0]
    if tvla:
        labels = ["Fixed", "Random"]
        means  = [tvla["fixed_mean_ms"], tvla["random_mean_ms"]]
        bars = ax1.bar(labels, means, color=[PLOT_COLORS[0], PLOT_COLORS[1]], alpha=0.85)
        for bar, m in zip(bars, means):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                     f"{m:.4f} ms", ha="center", va="bottom", fontsize=9)
        ax1.set_ylabel("Mean Decapsulation Time (ms)")
        ax1.set_title(f"TVLA Fixed vs.\\ Random\n"
                      f"$t={tvla['t_statistic']:.3f}$ "
                      f"(threshold $\\pm{tvla['threshold']}$) \u2014 "
                      f"{'PASS' if tvla['passed'] else 'LEAK DETECTED'}")
    else:
        ax1.axis("off")
        ax1.text(0.5, 0.5, "No TVLA data", ha="center", va="center")

    # --- Right: CV% relative to AES-256-GCM baseline ---
    ax2 = axes[1]
    if cv:
        aes   = cv.get("aes_gcm_baseline", {})
        proxy = cv.get("pqc_proxy_decapsulate", {})
        labels = ["AES-256-GCM\n(baseline)", "PQCProxy\ndecapsulate()"]
        cvs    = [aes.get("cv_pct", 0), proxy.get("cv_pct", 0)]
        bars = ax2.bar(labels, cvs, color=[PLOT_COLORS[2], PLOT_COLORS[3]], alpha=0.85)
        for bar, v in zip(bars, cvs):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
                     f"{v:.1f}%", ha="center", va="bottom", fontsize=9)
        ax2.set_ylabel("Coefficient of Variation (%)")
        ax2.set_title("Timing Variability vs.\\ Same-Run\nAES-256-GCM Baseline")
    else:
        ax2.axis("off")
        ax2.text(0.5, 0.5, "No CV baseline data", ha="center", va="center")

    plt.suptitle("Timing Side-Channel Analysis \u2014 ML-KEM-768 Architecture Path", fontsize=12)
    plt.tight_layout(); _save("sidechannel_timing.png")


def plot_esp32_memory():
    try:
        esp = load_json("esp32_results.json")
        free_kb = esp.get("free_heap_bytes", 0) / 1024
    except FileNotFoundError:
        logger.warning("esp32_results.json not found \u2014 skipping esp32_memory.png")
        return
    requirements = {"ML-KEM-512": 614, "ML-KEM-768": 900, "ML-KEM-1024": 1200}
    fig, ax = plt.subplots(figsize=(8, 5))
    ax.axhline(y=free_kb, color=PLOT_COLORS[0], linewidth=2.5,
               linestyle="--", label=f"ESP32-S3 free heap ({free_kb:.0f} KB)")
    names  = list(requirements.keys())
    values = [requirements[n] for n in names]
    bars   = ax.bar(names, values, color=[PLOT_COLORS[1], PLOT_COLORS[2], PLOT_COLORS[3]],
                    alpha=0.85, label="ML-KEM working memory required")
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
                f"{v} KB", ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.set_ylabel("Memory (KB)")
    ax.set_title("ESP32-S3 Available SRAM vs ML-KEM Memory Requirements\n"
                 "Empirical proof of device-side infeasibility")
    ax.legend(); ax.set_ylim(0, max(values) * 1.2)
    plt.tight_layout(); _save("esp32_memory.png")


def plot_stress_throughput():
    try:
        data = load_json("stress_benchmarks.json")["results"]
    except FileNotFoundError:
        logger.warning("stress_benchmarks.json not found \u2014 skipping stress plots")
        return

    concurrent = data.get("concurrent", {})
    if concurrent:
        threads    = [v["threads"]            for v in concurrent.values()]
        throughput = [v["throughput_per_sec"] for v in concurrent.values()]
        latency    = [v["mean_latency_ms"]    for v in concurrent.values()]
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
        ax1.plot(threads, throughput, "o-", color=PLOT_COLORS[0])
        ax1.set_xlabel("Concurrent Threads"); ax1.set_ylabel("Sessions / second")
        ax1.set_title("Throughput vs Concurrency")
        ax2.plot(threads, latency, "s-", color=PLOT_COLORS[2])
        ax2.set_xlabel("Concurrent Threads"); ax2.set_ylabel("Mean Latency (ms)")
        ax2.set_title("Latency vs Concurrency")
        plt.suptitle("ML-KEM-768 Proxy Stress Test \u2014 Raspberry Pi 4B", fontsize=12)
        plt.tight_layout(); _save("stress_concurrent.png")

    throughput_data = data.get("throughput", {})
    mem = throughput_data.get("memory", {})
    if mem:
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.bar(["Start", "End"], [mem["start_kb"], mem["end_kb"]],
               color=[PLOT_COLORS[0], PLOT_COLORS[2]], alpha=0.85)
        ax.set_ylabel("Process Memory (KB)")
        ax.set_title(f"Memory Usage: {STRESS_SESSIONS_TOTAL} Sequential Sessions\n"
                     f"Growth: {mem['growth_kb']:.1f} KB "
                     f"({'leak detected' if mem['leak_detected'] else 'no leak'})")
        plt.tight_layout(); _save("stress_memory.png")


def plot_extrapolation():
    try:
        data = load_json("stress_benchmarks.json")["results"]
        ext  = data.get("extrapolation", {})
    except FileNotFoundError:
        return
    scenarios = ["Pi 4B\n(1 core)", "Pi 4B\n(4 cores)",
                 "Cloud\n8-core", "Cloud\n32-core"]
    values    = [
        ext.get("pi4b_single_core_sps", 0),
        ext.get("pi4b_all_cores_sps", 0),
        ext.get("cloud_8core_instance_sps", 0),
        ext.get("cloud_32core_instance_sps", 0),
    ]
    fig, ax = plt.subplots(figsize=(8, 5))
    bars = ax.bar(scenarios, values, color=PLOT_COLORS, alpha=0.85)
    for bar, v in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                f"{v:.0f}", ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.set_ylabel("Sessions / Second")
    ax.set_title("ML-KEM-768 Proxy Throughput Extrapolation\n"
                 "(measured on Pi 4B, extrapolated to cloud)")
    plt.tight_layout(); _save("stress_extrapolation.png")


def generate_all_plots():
    logger.info("Generating all plots...")
    plot_latency_comparison()
    plot_energy_comparison()
    plot_handshake_comparison()
    plot_network_impact()
    plot_sidechannel_timing()
    plot_esp32_memory()
    plot_stress_throughput()
    plot_extrapolation()
    logger.info(f"All plots saved to: {PLOTS_DIR}")
