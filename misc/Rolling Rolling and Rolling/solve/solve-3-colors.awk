#!/usr/bin/awk -f

BEGIN {
  RS="m"
  FS=";"
}

{printf "%02x%02x%02x", $3, $4, $5}
