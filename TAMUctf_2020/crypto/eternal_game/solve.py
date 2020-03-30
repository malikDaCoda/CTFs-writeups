#!/usr/bin/env python2

import hlextend
from pwn import *

# wanted score = '1'*50

known_data = '1'
append = '1'*50

host = 'challenges.tamuctf.com'
port = 8812

length_range = range(10, 20)
# generated with get_signature()
signature = 'a17b713167841563563ac6903a8bd44801be3c0fb81b086a4816ea457f8c829a6d5d785b49161972b7e94ff9790d37311e12b32221380041a99c16d765e8776c'

# returns sha512(key + '1')
def get_signature():
  global game
  game.sendlineafter('3. Exit\n', '1') # option 1: New Game
  game.sendlineafter('3. Get proof and quit\n', '3') # option 3: Get proof and quit
  return game.recvuntil('\n').strip()

# with payload being the supposedly score and proof being the sha512 sum
def claim_prize(payload, proof):
  global game
  game.sendlineafter('3. Exit\n', '2') # option 2: Claim prize
  game.sendlineafter('Input the number you reached: \n', payload) # input the score reached ^^
  game.sendlineafter('Present the proof of your achievement: \n', proof) # input the proof ^^
  answer = game.recvline()
  print answer
  # If it starts with that string, it means that we're wrong in the length
  return not answer.startswith("Don't play games with me")

if __name__ == '__main__':
  game = remote(host, port)
  for key_len in length_range:
    print "\n[+] Trying key length:", key_len
    h = hlextend.new('sha512')
    # the extend function returns the `known_data + padding + append`
    # which will be our payload
    payload = h.extend(append, known_data, key_len, signature)
    # for some reason '\x80' and '\x00' are escaped...
    payload = payload.replace('\\x00', '\x00').replace('\\x80', '\x80')
    proof = h.hexdigest()
    
    if claim_prize(payload, proof):
      break
