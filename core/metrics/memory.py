"""Memory measurement utilities."""

import os


def get_memory_kb() -> float:
    try:
        import psutil
        return psutil.Process(os.getpid()).memory_info().rss / 1024.0
    except ImportError:
        try:
            with open("/proc/self/status") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        return float(line.split()[1])
        except Exception:
            pass
    return 0.0


def get_temperature() -> float:
    try:
        return int(
            open("/sys/class/thermal/thermal_zone0/temp").read().strip()
        ) / 1000.0
    except FileNotFoundError:
        return -1.0


def get_cpu_freq_mhz() -> float:
    try:
        return int(
            open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq").read().strip()
        ) / 1000.0
    except FileNotFoundError:
        return -1.0


def get_system_info() -> dict:
    import platform
    from datetime import datetime
    return {
        "platform"    : platform.platform(),
        "processor"   : platform.processor(),
        "python"      : platform.python_version(),
        "timestamp"   : datetime.now().isoformat(),
        "cpu_freq_mhz": get_cpu_freq_mhz(),
        "cpu_temp_c"  : get_temperature(),
    }
