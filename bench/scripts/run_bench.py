#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import subprocess
from pathlib import Path


def read_cmake_cache_value(cache_path: Path, key: str, default: str) -> str:
    if not cache_path.exists():
        return default

    pattern = re.compile(rf"^{re.escape(key)}:[^=]*=(.*)$")
    for line in cache_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        matched = pattern.match(line)
        if matched:
            return matched.group(1)
    return default


def find_benchmark_executable(build_dir: Path, config: str) -> Path:
    candidates = [
        build_dir / "bench" / "fastoml_bench_parse.exe",
        build_dir / "bench" / "fastoml_bench_parse",
        build_dir / "bench" / config / "fastoml_bench_parse.exe",
        build_dir / "bench" / config / "fastoml_bench_parse",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("benchmark executable not found")


def run_command(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and run fastoml benchmarks")
    parser.add_argument("--build-dir", default="build", help="Build directory path")
    parser.add_argument("--config", default="Release", help="Build configuration")
    parser.add_argument("--generator", default="", help="CMake generator")
    parser.add_argument(
        "--benchmark-filter",
        default="",
        help="Optional benchmark filter, passed as --benchmark_filter",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    build_dir = Path(args.build_dir)
    if not build_dir.is_absolute():
        build_dir = repo_root / build_dir

    cmake_args = [
        "cmake",
        "-S",
        str(repo_root),
        "-B",
        str(build_dir),
        "-DFASTOML_BENCH=ON",
        f"-DCMAKE_BUILD_TYPE={args.config}",
    ]
    cache_path = build_dir / "CMakeCache.txt"
    if args.generator:
        cmake_args.extend(["-G", args.generator])
    elif not cache_path.exists() and shutil.which("ninja") is not None:
        cmake_args.extend(["-G", "Ninja"])

    run_command(cmake_args)
    run_command(
        ["cmake", "--build", str(build_dir), "--config", args.config, "--target", "fastoml_bench_parse"]
    )

    repetitions = read_cmake_cache_value(cache_path, "FASTOML_BENCH_REPETITIONS", "10")
    warmup_sec = read_cmake_cache_value(cache_path, "FASTOML_BENCH_WARMUP_SEC", "0.1")
    output_json = read_cmake_cache_value(cache_path, "FASTOML_BENCH_OUTPUT_JSON", "bench-results.json")

    results_dir = build_dir / "bench-results"
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    output_base = Path(output_json).stem
    output_ext = Path(output_json).suffix or ".json"
    output_path = results_dir / f"{output_base}-{timestamp}{output_ext}"

    exe_path = find_benchmark_executable(build_dir, args.config)
    bench_cmd = [
        str(exe_path),
        f"--benchmark_repetitions={repetitions}",
        f"--benchmark_min_warmup_time={warmup_sec}",
        "--benchmark_report_aggregates_only=true",
        f"--benchmark_out={output_path}",
        "--benchmark_out_format=json",
    ]
    if args.benchmark_filter:
        bench_cmd.append(f"--benchmark_filter={args.benchmark_filter}")

    run_command(bench_cmd, cwd=exe_path.parent)
    print(f"benchmark results: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
