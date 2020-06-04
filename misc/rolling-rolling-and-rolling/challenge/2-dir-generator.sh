#!/bin/bash

# generate a hierarchy of directories that include randomly generated files
# and files in $files

DEPTH=4
NB_DIRS=3 # per level
NB_FILES=4 # per dir
MAX_SIZE=2000 # max random files' sizes in bytes
OUT_DIR="tmp" # dir where to generate the hierarchy
DIRNAME_FORMAT="maybehere-%03d" # used by printf
DEBUG=on # set this to anything to add verbosity
INCLUDE_DIR='include' # dir where files to include are located
files=("$PWD/$INCLUDE_DIR"/*) # files to include

# generate random dummy files in temp dir
mkdir ${DEBUG:+"-v"} $$ || \
  (echo "$0: could not create $$ directory" >&2 && exit 1)
((nb_files = NB_DIRS**DEPTH * NB_FILES - ${#files[@]}))
for ((i=0; i < nb_files; i++)); do
  ((size = RANDOM % MAX_SIZE + 1))
  filename="$(head -c6 /dev/urandom | base64 | tr -d '/')"
  ((RANDOM % 2)) && \
    # random ASCII (base64)
    head -c$size /dev/urandom | base64 >"$$/$filename" || \
    # random binary stuff
    head -c$size /dev/urandom >"$$/$filename"
  [ "$DEBUG" ] && echo "$0: created $$/$filename"
  files=("${files[@]}" "$PWD/$$/$filename")
done
files=($(shuf -e "${files[@]}"))

# create the directory hierarchy using recursion
max_nb_dirs=0
for ((i = 0; i <= $DEPTH; i++)); do
  ((max_nb_dirs += NB_DIRS**i))
done
dc=0 # dir count
fc=0 # file count
fill_dir() {
  local level=$1

  # if it's the last level we just put the files in the dir
  if (($level <= 0)); then
    for ((i=0; i < $NB_FILES; i++)); do
      cp "${files[$fc+$i]}" .
    done
    ((fc += NB_FILES))
  # else we create the dirs and call this function on each one
  else
    # to avoid accidents
    ((dc >= $max_nb_dirs)) && \
      (echo "$0: exceeded number of dirs to create" >&2 && exit 1)

    for ((i=0; i < $NB_DIRS; i++)); do
      mkdir ${DEBUG:+"-v"} $(printf "$DIRNAME_FORMAT" $((dc+i))) || \
        (echo "$0: could not create $$ directory" >&2 && exit 1)
    done
    ((dc += NB_DIRS))
    for dir in */; do
      cd "$dir"
      fill_dir $((level - 1))
      cd ..
    done
  fi
}

cd "$OUT_DIR" || \
    (echo "$0: could not cd to $OUT_DIR" >&2 && exit 1)
fill_dir $DEPTH
cd ..

# clean-up
rm -r ${DEBUG:+"-v"} "$$"
