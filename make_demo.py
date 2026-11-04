#!/usr/bin/env python3
"""Generate a synthetic Ethernet/IPv4 capture offline, never send packets."""
import argparse
import ipaddress
from pathlib import Path
import struct


def checksum(data):
    if len(data)%2:
        data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16:
        total=(total & 65535)+(total>>16)
    return (~total)&65535


def frame(protocol,payload,src='192.0.2.10',dst='198.51.100.20'):
    a,b=ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed
    ip=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),1,0,64,protocol,0,a,b)
    ip=ip[:10]+struct.pack('!H',checksum(ip))+ip[12:]
    return bytes.fromhex('0200000000020200000000010800')+ip+payload


def tcp_frame(port,flags=2):
    segment=struct.pack('!HHIIBBHHH',45000,port,1,0,0x50,flags,4096,0,0)
    pseudo=ipaddress.ip_address('192.0.2.10').packed+ipaddress.ip_address('198.51.100.20').packed+struct.pack('!BBH',0,6,len(segment))
    segment=segment[:16]+struct.pack('!H',checksum(pseudo+segment))+segment[18:]
    return frame(6,segment)


def dns_frame():
    # .test is an intentionally synthetic name; no lookup is performed.
    question=b'\x04demo\x04test\x00'+struct.pack('!HH',1,1)
    dns=struct.pack('!6H',1,0x0100,1,0,0,0)+question
    udp=struct.pack('!4H',53000,53,8+len(dns),0)+dns
    return frame(17,udp,dst='203.0.113.53')


def capture(frames,order='<',nano=False):
    magic={( '<',False):b'\xd4\xc3\xb2\xa1',('>',False):b'\xa1\xb2\xc3\xd4',('<',True):b'\x4d\x3c\xb2\xa1',('>',True):b'\xa1\xb2\x3c\x4d'}[(order,nano)]
    result=magic+struct.pack(order+'HHIIII',2,4,0,0,65535,1)
    for i,data in enumerate(frames):
        result+=struct.pack(order+'IIII',1767225600+i,0,len(data),len(data))+data
    return result


def block(order, block_type, body):
    """PCAPNG block with 32-bit padding and matching length fields."""
    body += b'\0'*(-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(order+'II', block_type, length)+body+struct.pack(order+'I', length)


def capture_pcapng(frames, order='<', nano=False):
    """Same synthetic frames as a first-section PCAPNG with Ethernet EPBs."""
    bom = b'\x4d\x3c\x2b\x1a' if order == '<' else b'\x1a\x2b\x3c\x4d'
    out = block(order, 0x0A0D0D0A, bom+struct.pack(order+'HHq', 1, 0, -1))
    idb = struct.pack(order+'HHI', 1, 0, 65535)
    if nano:
        idb += struct.pack(order+'HH', 9, 1)+b'\x09'+b'\0'*3+struct.pack(order+'HH', 0, 0)
    out += block(order, 1, idb)
    for i, data in enumerate(frames):
        units = (1767225600+i)*(1000000000 if nano else 1000000)
        epb = struct.pack(order+'IIIII', 0, units >> 32, units & 0xffffffff, len(data), len(data))+data
        out += block(order, 6, epb)
    return out


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',nargs='?',default='demo.pcap')
    parser.add_argument('--pcapng',action='store_true',help='write a PCAPNG capture instead of classic PCAP')
    args=parser.parse_args(argv)
    target=Path(args.output)
    frames=[tcp_frame(p) for p in range(20,32)]+[dns_frame()]
    # Never replace an existing capture, even if it is a symlink.
    with target.open('xb') as handle:
        handle.write(capture_pcapng(frames) if args.pcapng else capture(frames))
    print('Generated 13 synthetic packets:',target)


if __name__=='__main__':
    main()
