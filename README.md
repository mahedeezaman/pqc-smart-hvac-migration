# PQC Migration in Smart HVAC Systems

This repository contains the source code, experimental benchmark results, analysis scripts, and reproduction materials for the research paper:

**A Non-Invasive Cloud-Based Migration Strategy for Post-Quantum Cybersecurity in Smart HVAC Systems: Architecture, Implementation, and Empirical Evaluation**

## 1. Overview

This project evaluates a non-invasive proxy-based approach for introducing post-quantum cryptography (PQC) into smart HVAC systems without modifying existing HVAC controllers, their firmware, or vendor cloud infrastructure.

The implementation evaluates the following cryptographic configuration:

- **Key Encapsulation:** ML-KEM-768 (FIPS 203)
- **Digital Signature:** ML-DSA-65 (FIPS 204)
- **Key Derivation:** HKDF-SHA-256
- **Authenticated Encryption:** AES-256-GCM

A classical X25519 and Ed25519 implementation is included as a performance baseline.

## 2. Repository Structure

| Directory/File | Description |
|---|---|
| `core/` | Cryptographic implementations, performance metrics, and statistical utilities |
| `benchmarks/` | Cryptographic operation, end-to-end, network, and stress benchmarks |
| `analysis/` | Side-channel analysis, ESP32-S3 feasibility analysis, and plotting utilities |
| `infra/` | Benchmark configuration, logging, and result storage |
| `tests/` | PQC handshake and classical ECDH integration tests |
| `results/` | Raw JSON and CSV benchmark results, ESP32-S3 measurements, and generated LaTeX tables |
| `plots/` | Generated experimental figures |
| `output/` | LaTeX table generation utilities |
| `logs/` | Benchmark execution logs |
| `run.py` | Main benchmark execution script |
| `HowToRun.txt` | Basic execution instructions |

## 3. Experimental Environment

The primary benchmarks were conducted on a Raspberry Pi 4B with a 64-bit Linux operating system and Python 3.13.5.

An ESP32-S3 development board was also used for device-side memory and cryptographic feasibility measurements.

The benchmark configuration is maintained in:

`infra/config.py`

Important experimental parameters include:

| Parameter | Configuration |
|---|---:|
| Warm-up runs | 50 |
| Measured runs | 500 |
| Inter-run delay | 10 ms |
| Network RTT simulations | 0, 20, 50, 100, 250 ms |
| Sequential stress sessions | 500 |
| Concurrent sessions | Up to 32 |
| TVLA samples per group | 50,000 |
| Nonce collision samples | 10,000 |

## 4. Requirements

The benchmark environment requires:

- Python 3.13.5 (version used in the reported experiments)
- Open Quantum Safe `liboqs` library
- Python bindings for `liboqs` (`oqs`)
- `cryptography`
- `psutil`
- `numpy`
- `matplotlib`

The native `liboqs` library and its Python bindings must be installed and configured before executing the PQC benchmarks.

No pinned dependency file is currently included. The benchmark configuration and execution parameters can be inspected in `infra/config.py`.

## 5. Running the Experiments

Execute the following commands from the repository root.

**Run the complete benchmark suite:**

```bash
python3 run.py all
```

**Run integration tests:**

```bash
python3 run.py test
```

**Run individual benchmarks:**

```bash
python3 run.py benchmark operations
python3 run.py benchmark e2e
python3 run.py benchmark network
python3 run.py benchmark stress
```

**Run security and device feasibility analyses:**

```bash
python3 run.py analysis sidechannel
python3 run.py analysis esp32
```

**Generate plots and LaTeX tables:**

```bash
python3 run.py output plots
python3 run.py output tables
```

The complete execution sequence, including CPU frequency configuration, is also documented in `HowToRun.txt`.

## 6. Experimental Data

The repository includes the experimental data supporting the study:

- `results/operation_benchmarks.json` and `results/operation_benchmarks.csv`: Cryptographic operation measurements.
- `results/e2e_benchmarks.json`: End-to-end handshake measurements.
- `results/network_benchmarks.json`: Network latency benchmark results.
- `results/stress_benchmarks.json`: Throughput, concurrency, and memory measurements.
- `results/sidechannel_analysis.json`: Security and side-channel analysis results.
- `results/esp32_results.json` and `results/esp32_results.txt`: ESP32-S3 hardware measurements and feasibility results.
- `results/latex_tables.tex`: Generated LaTeX tables.
- `plots/`: Generated figures used for experimental analysis.

The ESP32-S3 results are provided as recorded experimental data. The corresponding device firmware source is not included in this repository.

## 7. Reproducibility Notes

The benchmark parameters can be modified in `infra/config.py`.

For comparable results, use consistent hardware, operating-system configuration, CPU frequency, cryptographic library versions, and benchmark parameters.

Network latency experiments use simulated delays rather than measurements from a physical network. Energy consumption is estimated using the configured CPU power model rather than direct external power measurements.

The included JSON and CSV files preserve the experimental results reported in the study.

## Copyright and License

Copyright (c) 2026 Mahedee Zaman Moon.

This project is licensed under the MIT License. You are free to use, modify, distribute, and commercially use this software, subject to the terms and conditions of the MIT License. See the [LICENSE](LICENSE) file for details.

## Academic Citation

If you use this implementation in academic research, please cite the associated research paper:

Mahedee Zaman Moon, Kaysarul Anas Apurba, Md Hasibul Hasan, Atsuo Inomata, and Sk Md Mizanur Rahman, "A Non-Invasive Cloud-Based Migration Strategy for Post-Quantum Cybersecurity in Smart HVAC Systems: Architecture, Implementation, and Empirical Evaluation."

Please cite the published version when available.

