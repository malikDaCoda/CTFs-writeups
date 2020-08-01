#!/bin/sh

# exit on error
set -e

# work in this folder
mkdir -p extract_dir && cd extract_dir

# initial file
FILE="../pop.zip"

# 7z can extract zip, gzip, xz, bzip2 and many more
# in bourne shell (/bin/sh) redirect stdout and stderr using `>/path/to/file 2>&1`
while 7z -y e "$FILE" >/dev/null 2>&1; do
    echo "[*] Current file: $FILE ($(wc -c <$FILE) bytes)"
    # set the filenames of the current folder as positional arguments (sorted by the time of change)
    set $(ls -t --time=ctime)
    # first arg is the most recent created file (the one that has just been extracted)
    FILE="$1"
    # delete the rest of the files
    shift && [ "$@" ] && rm "$@"
done

echo "No more files to decompress !"
# print the flag
cat *
