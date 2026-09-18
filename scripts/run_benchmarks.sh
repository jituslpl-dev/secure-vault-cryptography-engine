#!/usr/bin/env bash
# ============================================================================
# SecureVault — Automated Benchmark Runner
# Runs C++ benchmarks and captures results for throughput, latency, and memory.
# ============================================================================

set -euo pipefail

BUILD_DIR="${BUILD_DIR:-build}"
RESULTS_DIR="benchmark_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
RESULT_FILE="${RESULTS_DIR}/bench_${TIMESTAMP}.txt"

mkdir -p "$RESULTS_DIR"

echo "╔═════════════════════════════════════════════════════╗"
echo "║   SecureVault — Automated Benchmark Suite            ║"
echo "╚═════════════════════════════════════════════════════╝"
echo ""

# ─── Build ────────────────────────────────────────────────────────
echo "▸ Building benchmarks..."
cmake -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Release \
      -DSECUREVAULT_BUILD_BENCHMARKS=ON \
      -DSECUREVAULT_BUILD_TESTS=OFF 2>&1 | tail -5

cmake --build "$BUILD_DIR" --target securevault_bench -j 2>&1 | tail -5

# ─── Run C++ Benchmarks ───────────────────────────────────────────
echo ""
echo "▸ Running C++ benchmarks..."
echo "========================================" | tee "$RESULT_FILE"
echo "  SecureVault Benchmark Results" | tee -a "$RESULT_FILE"
echo "  Date: $(date)" | tee -a "$RESULT_FILE"
echo "  OS: $(uname -s) $(uname -r)" | tee -a "$RESULT_FILE"
echo "  CPU: $(grep 'model name' /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs || echo 'N/A')" | tee -a "$RESULT_FILE"
echo "========================================" | tee -a "$RESULT_FILE"

"$BUILD_DIR/securevault_bench" 2>&1 | tee -a "$RESULT_FILE"

# ─── Memory Usage (Valgrind massif, if available) ────────────────
if command -v valgrind &>/dev/null; then
    echo ""
    echo "▸ Running memory analysis (Valgrind massif)..."
    valgrind --tool=massif --massif-out-file="$RESULTS_DIR/massif_${TIMESTAMP}.out" \
             "$BUILD_DIR/securevault_bench" 2>&1 | tail -5

    if command -v ms_print &>/dev/null; then
        echo "▸ Memory usage summary:" | tee -a "$RESULT_FILE"
        ms_print "$RESULTS_DIR/massif_${TIMESTAMP}.out" 2>&1 | tee -a "$RESULT_FILE"
    fi
else
    echo "▸ Valgrind not found — skipping memory analysis"
fi

# ─── Run Python Demo for Comparison ───────────────────────────────
if command -v python3 &>/dev/null; then
    echo ""
    echo "▸ Running Python reference implementation..." | tee -a "$RESULT_FILE"
    python3 test/demo_python.py 2>&1 | tee -a "$RESULT_FILE"
fi

echo ""
echo "▸ Results saved to: $RESULT_FILE"
echo ""



