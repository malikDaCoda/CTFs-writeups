#!/usr/bin/env python3
import itertools

# encrypted key1, key2 and flag (from scrambledeggs.txt)
ekey1 = 'xtfsyhhlizoiyx'
ekey2 = 'eudlqgluduggdluqmocgyukhbqkx'
eflag = 'lvvrafwgtocdrdzfdqotiwvrcqnd'

scramble_map = ['v', 'r', 't', 'p', 'w', 'g', 'n', 'c', 'o', 'b', 'a', 'f', 'm', 'i', 'l', 'u', 'h', 'z', 'd', 'q', 'j', 'y', 'x', 'e', 'k', 's']
# result of the evaluation of (sys.maxsize % 28) for 64-bit machines
randsize = 7
# to choose whether or not to swap key1 and key2
swapkeys = True
# write the resulting flag combinations to a file
outfile = 'results.txt'

# reverse enc1, but provide n
def dec1(text, n):
    assert(0 <= n < 28)
    return text[-n:] + text[:-n]

# reverse enc2
def dec2(text):
    # map each character of text to the character of order :
    # index of text[i] in scramble_map + ord('a')
    return ''.join(chr(scramble_map.index(char) + ord('a')) for char in text)

# recover key2 from the encrypted key2 (the part where random chars are appended to key2)
def recover_key2(ekey2):
    assert(len(ekey2) == 28)
    # the random characters are the 14 first
    k = ekey2[:14]
    # the list of `a`s
    alist = list(map(ord, ekey2[14:]))
    res = ''
    for i in range(14):
        # we simply compute c using linear equations
        c = alist[i] - ord(k[i]) + ord('a')
        # since all characters are ascii lowercase
        # this check helps avoiding multiple potential values
        if not ord('a') <= c <= ord('z'):
            c += 122 - 97
        res += chr(c)
    return res

# undo the big double loop
def unloop(key1, key2, flag):
    key1, key2, flag = list(key1), list(key2), list(flag)
    assert (len(key1) == len(key2) == 14)
    for j in range(2):
        # we make sure the range is from 27 to 14, not 14 to 27
        for i in range(27, 13, -1):
            # taking advantage of python's built-in way to swap values
            # rather than using a temp variable
            index = (ord(key1[i-14]) - ord('a')) % 14
            key2[index], key2[i-14] = key2[i-14], key2[index]

            index = (ord(key2[i-14]) - ord('a')) % 28
            flag[i], flag[index] = flag[index], flag[i]

        for i in range(13, -1, -1):
            index = (ord(key2[i]) - ord('a')) % 14
            key1[index], key1[i] = key1[i], key1[index]

            index = (ord(key1[i]) - ord('a')) % 28
            flag[i], flag[index] = flag[index], flag[i]

    return ''.join(key1), ''.join(key2), ''.join(flag)

if __name__ == '__main__':
    # generate the combinations of 3 `n`s using itertools.product
    combinations = [p for p in itertools.product(range(randsize+1), repeat=3)]
    key1 = ekey1
    key2 = recover_key2(dec2(ekey2))
    flag = dec2(eflag)
    if swapkeys: key1, key2 = key2, key1
    original = flag, key1, key2
    results = []
    for c in combinations:
        flag = dec1(dec1(dec1(flag, c[0]), c[1]), c[2])
        key1, key2, flag = unloop(key1, key2, flag)
        if dec2(dec2(key2)) == key1:
            for n in range(randsize + 1):
                flag = dec1(flag, n)
                results.append(flag)
        flag, key1, key2 = original
    with open(outfile, 'w') as f:
        f.write('\n'.join(results))
        f.close()
