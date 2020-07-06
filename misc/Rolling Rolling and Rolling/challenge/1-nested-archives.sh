#!/bin/bash

# create nested password protected archives 

FILES=(include/*) # array of files to include in last archive (flag for example)
FINAL_ARCHIVE_FILE="final.zip" # name of last archive
ARCHIVE='archive.zip' # name of nested archives
PASS_FILE='pass.txt' # name of password file
TYPE='zip'
NUM=100 # nesting count

zip -r "$FINAL_ARCHIVE_FILE" "${FILES[@]}" >/dev/null
pass=$(head -c16 /dev/urandom | xxd -p) # get 16 random bytes for password
7za a -t"$TYPE" -p"$pass" -mem=AES256 "$ARCHIVE" "$FINAL_ARCHIVE_FILE" >/dev/null

for ((i=0; i < $NUM-1; i++)); do
  echo "$pass" >"$PASS_FILE"
  pass=$(head -c16 /dev/urandom | xxd -p) # get 16 random bytes for password
  7za a -t"$TYPE" -p"$pass" -mem=AES256 "$$.$TYPE" "$ARCHIVE" "$PASS_FILE" >/dev/null
  mv "$$.$TYPE" "$ARCHIVE"
done

echo "$pass" >"$PASS_FILE"
rm "${FILES[@]}" "$FINAL_ARCHIVE_FILE"
