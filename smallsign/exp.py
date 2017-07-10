from pwn import *
import math

while True:
    r = remote('shell2017.picoctf.com', 27465)
    r.recvline()
    N = int(r.recvline().split(' ')[1])
    e = int(r.recvline().split(' ')[1])
    factors = {}

    def gen_primes():
        """ Generate an infinite sequence of prime numbers.
        """
        # Maps composites to primes witnessing their compositeness.
        # This is memory efficient, as the sieve is not "run forward"
        # indefinitely, but only as long as required by the current
        # number being tested.
        #
        D = {}

        # The running integer that's checked for primeness
        q = 2

        while True:
            if q not in D:
                # q is a new prime.
                # Yield it and mark its first multiple that isn't
                # already marked in previous iterations
                #
                yield q
                D[q * q] = [q]
            else:
                # q is composite. D[q] is the list of primes that
                # divide it. Since we've reached q, we no longer
                # need it in the map, but we'll mark the next
                # multiples of its witnesses to prepare for larger
                # numbers
                #
                for p in D[q]:
                    D.setdefault(p + q, []).append(p)
                del D[q]

            q += 1

    primes = gen_primes()

    p = next(primes)
    def get_sig(n):
        r.recvuntil(': ')
        r.send(str(n) + '\n')
        sig = r.recvline()
        return int(sig.split(' ')[1])

    while p <= 4000:
        factors[p] = get_sig(p)
        print (p, factors[p])
        
        p = next(primes) 

    r.recvuntil(': ')
    r.send('-1\n')
    chal = int(r.recvline().split(' ')[1])
    print(chal)

    a = chal
    sig = 1
    for f in factors:
        if a == 1:
            break
        print(f)
        while a % f == 0:
            a /= f
            sig *= factors[f]

    if a != 1:
        r.close()
        continue

    r.recvuntil('challenge: ')
    r.send('{}\n'.format(sig % N))

    print r.recvall()
    break
