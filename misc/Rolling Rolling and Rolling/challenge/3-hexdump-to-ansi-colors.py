#!/usr/bin/env python3

# convert a file to ANSI RGB color characters

rgb_format = '\x1b[48;2;{:d};{:d};{:d}m'
reset_format = '\x1b[0m\n'

# convert bytes to ANSI colors
def hex_to_ansicolors(hexdump):
  padding = 3 - len(hexdump) % 3
  hexdump += b'\x00' * padding
  output = ''
  for i in range(0, len(hexdump), 3):
    output += rgb_format.format(hexdump[i], hexdump[i+1], hexdump[i+2]) + ' '
  output += reset_format
  return output


if __name__ == '__main__':
  from sys import argv

  if len(argv) != 3:
    print('Usage: {} <in_file> <out_file>'.format(argv[0]))
  else:
    in_file = argv[1]
    out_file = argv[2]

    with open(in_file, 'rb') as f:
      content = f.read()
      f.close()

    converted = hex_to_ansicolors(content)

    with open(out_file, 'w') as f:
      f.write(converted)
      f.close()
