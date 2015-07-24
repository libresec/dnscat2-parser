#!/usr/bin/env python
# reference: https://github.com/jeffsilverm/dpkt_doc/blob/master/decode_dns.py

import binascii
import os
import pprint
import struct
import socket
import sys
import dpkt
import dpkt.dns


def gen_udp(packet):
    for ts, pkt in packet:
        # Check if IPv4
        eth = dpkt.ethernet.Ethernet(pkt)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            # Check if UDP
            if ip.p == dpkt.ip.IP_PROTO_UDP:
                udp = ip.data
                # Yield IP addresses, source port, destination port, and data
                # if UDP/53
                if udp.dport == 53 or udp.sport == 53:
                    yield (ip.src, udp.sport, ip.dst, udp.dport, udp.data)


def gen_dnscat2(packet):
    for src, sport, dst, dport, data in packet:

        dns = dpkt.dns.DNS(data)

        # Parse dnscat2 request
        if dport == 53:
            packet = dns.qd[0].name.replace(".", "").split('dnscat')[1]
            message = binascii.unhexlify(packet)
            message_type = struct.unpack('!Hb', message[:3])

        # Parse dnscat2 response
        elif sport == 53:
            for rr in dns.an:
                packet = rr.rdata[1:]
                message = binascii.unhexlify(packet)
                message_type = struct.unpack('!Hb', message[:3])

        # Message type 0 is SYN
        if message_type[1] == 0:
            syn = decode_syn(message, src, dst)
            yield syn

        # Message type 1 is MSG
        elif message_type[1] == 1:
            msg = decode_msg(message, src, dst)
            yield msg


def decode_msg(messageIn, src, dst):
    msg = struct.unpack('!HbH', messageIn[:5])
    msg_dict = {'request': binascii.hexlify(messageIn),
                'src': '%s' % (socket.inet_ntoa(src)),
                'dst': '%s' % (socket.inet_ntoa(dst)),
                'packet_id': msg[0],
                'msg_type': 'MSG',
                'session_id': msg[2],
                'payload': messageIn[9:].strip('\0')}
    return msg_dict


def decode_syn(messageIn, src, dst):
    syn = struct.unpack('!HbHHH', messageIn[:9])
    syn_dict = {'request': binascii.hexlify(messageIn),
                'src': '%s' % (socket.inet_ntoa(src)),
                'dst': '%s' % (socket.inet_ntoa(dst)),
                'packet_id': syn[0],
                'msg_type': 'SYN',
                'session_id': syn[2],
                'init_seq_num': syn[3],
                'session_name': messageIn[9:].strip('\0')}
    return syn_dict


def main(pcap, output=None):
    with open(pcap) as capture:
        pcap = dpkt.pcap.Reader(capture)
        udp_packets = gen_udp(pcap)
        dnscat2_packets = gen_dnscat2(udp_packets)
        activity = {}
        for p in dnscat2_packets:
            if p['session_id'] in activity:
                activity[p['session_id']].append(p)
            else:
                activity[p['session_id']] = [p]

        if not output:
            for session in activity:
                for entry in activity[session]:
                    if entry.get('session_name'):
                        print entry['session_name'].strip()
                    if entry.get('payload'):
                        print entry['payload'].strip()
        else:
            pprint.pprint(activity)

if __name__ == '__main__':
    if (len(sys.argv) == 2) and os.path.isfile(sys.argv[1]):
        main(sys.argv[1])
    elif (len(sys.argv) == 3) and (sys.argv[2] == '-v'):
        main(sys.argv[1], output=1)
    else:
        print '''
        Usage:
            python dnscat2-parser.py <pcap>
            python dnscat2-parser.py <pcap> -v
        '''
