import pyshark
import sys

pkts = pyshark.FileCapture('perdu.pcap', display_filter='tcp and tcp.flags.syn==1 and tcp.flags.ack==1')

for p in pkts:
    sys.stdout.write(chr(int(p.tcp.dstport)-4000))
