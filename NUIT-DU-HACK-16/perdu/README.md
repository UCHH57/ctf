# [NUIT DU HACK 16] perdu (Forensics-100pts)

## Discovery time !

In this task we were given a tcpdump capture file (pcap).

So we can open it with tool like Wireshark or NetworkMiner.
In this case we have used Wireshark.

In Whireshark we can see lots of exchange between only two ip addresses.
One seems to be a web server for a website called `perdu.com`.
We will call the other the client.

But one thing is weird in those exchange, the client use different port for each connection. 
```
tshark -r perdu.pcap | head -n 20
    1   0.000000  10.137.2.37 → 208.97.177.124 TCP 68 4010 → 80 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=64
    2   0.090453 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4010 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
    3   0.090504  10.137.2.37 → 208.97.177.124 TCP 56 4010 → 80 [ACK] Seq=1 Ack=1 Win=29248 Len=0
    4   0.090574  10.137.2.37 → 208.97.177.124 HTTP 91 GET / HTTP/1.1 
    5   0.182816 208.97.177.124 → 10.137.2.37  TCP 56 80 → 4010 [ACK] Seq=1 Ack=36 Win=29696 Len=0
    6   0.184252 208.97.177.124 → 10.137.2.37  HTTP 495 HTTP/1.1 200 OK  (text/html)
    7   0.184461  10.137.2.37 → 208.97.177.124 TCP 56 4010 → 80 [ACK] Seq=36 Ack=440 Win=30272 Len=0
    8   2.340002 208.97.177.124 → 10.137.2.37  TCP 56 80 → 4010 [FIN, ACK] Seq=440 Ack=36 Win=29696 Len=0
    9   2.340129  10.137.2.37 → 208.97.177.124 TCP 56 4010 → 80 [FIN, ACK] Seq=36 Ack=441 Win=30272 Len=0
   10   2.340314  10.137.2.37 → 208.97.177.124 TCP 68 4032 → 80 [SYN] Seq=0 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=64
   11   2.429761 208.97.177.124 → 10.137.2.37  TCP 56 80 → 4010 [ACK] Seq=441 Ack=37 Win=29696 Len=0
   12   2.434365 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4032 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   13   2.434496  10.137.2.37 → 208.97.177.124 TCP 56 4032 → 80 [ACK] Seq=1 Ack=1 Win=29248 Len=0
   14   2.434698  10.137.2.37 → 208.97.177.124 HTTP 91 GET / HTTP/1.1 
   15   2.523086 208.97.177.124 → 10.137.2.37  TCP 56 80 → 4032 [ACK] Seq=1 Ack=36 Win=29696 Len=0
   16   2.524149 208.97.177.124 → 10.137.2.37  HTTP 495 HTTP/1.1 200 OK  (text/html)
   17   2.524228  10.137.2.37 → 208.97.177.124 TCP 56 4032 → 80 [ACK] Seq=36 Ack=440 Win=30272 Len=0
   18   4.525903 208.97.177.124 → 10.137.2.37  TCP 56 80 → 4032 [FIN, ACK] Seq=440 Ack=36 Win=29696 Len=0
   19   4.526004  10.137.2.37 → 208.97.177.124 TCP 56 4032 → 80 [FIN, ACK] Seq=36 Ack=441 Win=30272 Len=0
   20   4.615210 208.97.177.124 → 10.137.2.37  TCP 56 80 → 4032 [ACK] Seq=441 Ack=37 Win=29696 Len=0
```
In the above extract we can see on line 4 and 14 the client requesting the root of the web server and on line 1 and 10 we can see he used two different port to do so. The first time he has used the port `4010` and the second time the port `4032`.

For each request on the website, 10 packets are exchanged so we define a filter to see only one packet per request. 
On those ten packets only one has tcp flags `SYN` and `ACK` simultaneously so we choose to use that as filter.
```
$ tshark -r perdu.pcap -Y "tcp.flags.syn==1 and tcp.flags.ack==1" | head
    2   0.090453 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4010 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   12   2.434365 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4032 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   22   4.715952 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4032 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   32   7.035176 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4032 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   42   9.338181 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4061 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   52  11.697453 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4061 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   62  13.899849 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4080 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   72  16.089017 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4104 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   82  18.409335 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4114 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
   92  20.658809 208.97.177.124 → 10.137.2.37  TCP 68 80 → 4097 [SYN, ACK] Seq=0 Ack=1 Win=29200 Len=0 MSS=1460 SACK_PERM=1 WS=1024
```
With this filter we now have only one packet per request.
We can now start to figure why those port are diferent and how they are used.

## Extraction time !

When we look at the first two port, an idea came at our mind.
The first two ports are `4010` and `4032` and we know that 10 in ascii corespond to  `'\n'` and 32 correspond to `SPACE`, so it is posible that the port is the decimal value of ascii character plus 4000.

To check our idea, we programmed a tiny python script:
```python
import pyshark
import sys

pkts = pyshark.FileCapture('perdu.pcap', display_filter='tcp and tcp.flags.syn==1 and tcp.flags.ack==1')

for p in pkts:
    sys.stdout.write(chr(int(p.tcp.dstport)-4000))
```
We run our script:
```
$ python3 port_exfiltration.py

   ==Phrack Inc.==

                    Volume One, Issue 7, Phile 3 of 10
[...]
        I am a hacker, and this is my manifesto.  You may stop this individual,
but you can't stop us all... after all, we're all alike.

                               +++The Mentor+++
Well done : ndh16_{e132697f156befd669df0726f06ab338f0a225da3267661cfa9bb720161b2af9}
```

**Et voilà !**
