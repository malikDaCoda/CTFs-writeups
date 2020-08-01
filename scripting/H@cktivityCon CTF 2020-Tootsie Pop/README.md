# Tootsie Pop (H@cktivityCon CTF 2020) (150 pts)

## Challenge description
> How many licks does it take to get to the center of a tootsie pop?

In this **scripting** challenge, we are provided with the archive file [pop.zip](https://github.com/malikDaCoda/CTFs-writeups/tree/master/scripting/H%40cktivityCon%20CTF%202020-Tootsie%20Pop/pop.zip), which recursively contains archive files of types: zip, gzip, xz and bzip2.

## Solution
There are numerous ways to solve this challenge, but I found the following solution to be the best :
1. extract from current file using `7z` (regardless of its file type)
2. make the extracted file (the most recent file) the current one
3. delete the other files
4. repeat step 1 until there are no more files to extract

Here's the script to achieve that :
```sh
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
```

After running the script, we read the **flag** :
```
flag{the_answer_is_1548_licks}
```
