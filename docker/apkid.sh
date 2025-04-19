#!/usr/bin/env bash

# This will simply take the argument passed to it,
# parse the directory and bind it as a read-only mount point on the container
# and pass in the filename as the argument to APKiD
#
# This can easily be set to an alias and added to your .profile or whatever

FILES=()
ARGS=()

for arg in "$@"; do
    if [[ -e "$arg" ]]; then
        FILES+=("$arg")
    else
        ARGS+=("$arg")
    fi
done

if [[ ${#FILES[@]} -eq 0 ]]; then
    docker run --rm -i rednaga:apkid "${ARGS[@]}"
    exit 0
fi

FIRST_FILE="${FILES[0]}"
INPUT_DIR=$(cd "$(dirname "$FIRST_FILE")" && pwd -P)

MAPPED_FILES=()
for file in "${FILES[@]}"; do
    MAPPED_FILES+=("/input/$(basename "$file")")
done

docker run --rm --volume "$INPUT_DIR":/input:ro -i rednaga:apkid "${ARGS[@]}" "${MAPPED_FILES[@]}"
