#!/bin/bash

ARCHIVE="archive.zip"
PASS_FILE="pass.txt"

until [ "$old_size" = "$(wc -c $ARCHIVE)" ]; do
  old_size=$(wc -c $ARCHIVE)
  7za e -p"$(cat $PASS_FILE)" $ARCHIVE -y >/dev/null
done
