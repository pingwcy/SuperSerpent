#!/bin/bash

# Configuration
ROOT_DIR="./d"
HASH_FILE="./file_hashes.txt"
NUM_FILES=500
NUM_WORKERS=8               # Number of parallel "threads"
MAX_DEPTH=5
MIN_SIZE_KB=10
MAX_SIZE_KB=10240

# Cleanup from previous runs
rm -rf "$ROOT_DIR" "$HASH_FILE"
mkdir -p "$ROOT_DIR"
mkdir -p "$ROOT_DIR/tmp_hashes"

# Generate random files in parallel
generate_files() {
    local start_idx=$1
    local end_idx=$2
    local worker_id=$3
    local tmp_hash_file="$ROOT_DIR/tmp_hashes/hashes_worker_$worker_id.txt"

    for ((i = start_idx; i <= end_idx; i++)); do
        # Random folder path
        depth=$((RANDOM % MAX_DEPTH + 1))
        subdir="$ROOT_DIR"
        for ((d = 1; d <= depth; d++)); do
            subdir="$subdir/dir_$((RANDOM % 10000))"
        done
        mkdir -p "$subdir"

        # Random file and content
        filename="file_$((RANDOM % 100000)).bin"
        filepath="$subdir/$filename"
        size_kb=$((RANDOM % (MAX_SIZE_KB - MIN_SIZE_KB + 1) + MIN_SIZE_KB))

        head -c "$((size_kb * 1024))" /dev/urandom > "$filepath"
        md5sum "$filepath" >> "$tmp_hash_file"
    done
}

echo "Spawning $NUM_WORKERS threads to generate $NUM_FILES files..."

# Split work across workers
files_per_worker=$((NUM_FILES / NUM_WORKERS))
remainder=$((NUM_FILES % NUM_WORKERS))
start=1

for ((w = 0; w < NUM_WORKERS; w++)); do
    end=$((start + files_per_worker - 1))
    [[ $w -eq $((NUM_WORKERS - 1)) ]] && end=$((end + remainder)) # Handle remainder
    generate_files "$start" "$end" "$w" &
    start=$((end + 1))
done

wait
cat "$ROOT_DIR/tmp_hashes/"*.txt > "$HASH_FILE"
rm -r "$ROOT_DIR/tmp_hashes"

echo "File generation complete. Starting integrity verification in $NUM_WORKERS threads..."

# Parallel verification
verify_hashes() {
    local hashfile=$1
    local failed=0

    while read -r hash path; do
        if ! echo "$hash  $path" | md5sum -c --quiet -; then
            echo "Mismatch: $path"
            ((failed++))
        fi
    done < "$hashfile"
    return $failed
}

# Split hash file into chunks for parallel verification
split -n l/$NUM_WORKERS "$HASH_FILE" "$ROOT_DIR/hash_chunk_"

FAIL_COUNT=0
for chunk in "$ROOT_DIR"/hash_chunk_*; do
    verify_hashes "$chunk" &
done

wait

for job in $(jobs -p); do
    wait $job || ((FAIL_COUNT += $?))
done

echo "Verification complete. $FAIL_COUNT file(s) failed integrity check out of $NUM_FILES."

exit $FAIL_COUNT

