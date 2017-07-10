from pwn import *

inp = """0x804a008:      0x0804a018      0x0804a148      0x00000079      0x00000011
0x804a018:      0x0804a028      0x0804a068      0x00000075      0x00000011
0x804a028:      0x0804a048      0x0804a038      0x0000006f      0x00000011
0x804a038:      0x0804a078      0x00000000      0x00000074      0x00000011
0x804a048:      0x0804a058      0x0804a0a8      0x00000065      0x00000011
0x804a058:      0x0804a168      0x0804a0e8      0x00000061      0x00000011
0x804a068:      0x00000000      0x0804a088      0x00000076      0x00000011
0x804a078:      0x00000000      0x0804a098      0x00000070      0x00000011
0x804a088:      0x0804a108      0x00000000      0x00000078      0x00000011
0x804a098:      0x00000000      0x0804a0b8      0x00000071      0x00000011
0x804a0a8:      0x0804a118      0x0804a0c8      0x00000067      0x00000011
0x804a0b8:      0x00000000      0x0804a0d8      0x00000072      0x00000011
0x804a0c8:      0x0804a0f8      0x0804a188      0x0000006c      0x00000011
0x804a0d8:      0x00000000      0x00000000      0x00000073      0x00000011
0x804a0e8:      0x0804a178      0x00000000      0x00000064      0x00000011
0x804a0f8:      0x00000000      0x0804a128      0x00000068      0x00000011
0x804a108:      0x00000000      0x00000000      0x00000077      0x00000011
0x804a118:      0x00000000      0x00000000      0x00000066      0x00000011
0x804a128:      0x0804a158      0x0804a138      0x0000006a      0x00000011
0x804a138:      0x00000000      0x00000000      0x0000006b      0x00000011
0x804a148:      0x00000000      0x00000000      0x0000007a      0x00000011
0x804a158:      0x00000000      0x00000000      0x00000069      0x00000011
0x804a168:      0x00000000      0x00000000      0x0000005f      0x00000011
0x804a178:      0x0804a198      0x00000000      0x00000063      0x00000011
0x804a188:      0x00000000      0x0804a1a8      0x0000006d      0x00000011
0x804a198:      0x00000000      0x00000000      0x00000062      0x00000011"""

def und(x):
    return int(x,16)

mapping = {}
for l in inp.split('\n'):
    address,r = l.split(':')
    r = r.strip().replace('      ',' ').replace('       ',' ')
    print(address,r)
    mapping[und(address)] = map(und, r.split(' ')[:3])

st = 'DLLDLDLLLLLDLLLLRLDLLDLDLLLRRDLLLLRDLLLLLDLLRLRRRDLLLDLLLDLLLLLDLLRDLLLRRLDLLLDLLLLLDLLLRLDLLDLLRLRRDLLLDLLRLRRRDLLRDLLLLLDLLLRLDLLDLLRLRRDLLLLLDLLRDLLLRRLDLLLDLLLLLDLLRDLLRLRRDLLLDLLLDLLRLRRRDLLLLLDLLLLRLDLLLRRLRRDDLLLRRDLLLRRLRDLLLRLDLRRDDLLLRLDLLLRRRDLLRLRRRDLRRLD'

cur = 0x804a008
p = ''
for ch in st:
    print(ch,cur)
    print(mapping[cur])
    if ch == 'D':
        p += chr(mapping[cur][2])
        cur = 0x804a008
    elif ch == 'R':
        cur = mapping[cur][1]
    elif ch == 'L':
        cur = mapping[cur][0]
print(p)


