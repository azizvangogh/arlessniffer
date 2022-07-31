import socket
import struct
import textwrap


TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, proto))
        print('Data: {}'.format(data))

        if eth_proto == 8:
            (version , ihl , iph_length , ttl , proto , src , target , data) = unpack_ip(data)
            print (TAB_1 + 'IPv4 Packet:')
            print (TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, ihl, ttl))
            print (TAB_2 + 'Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))
            
            if proto == 1:
                (imcp_type , code , checksum , data) = imcp_packet(data)
                print (TAB_2 + 'ICMP Packet:')
                print (TAB_3 + 'Type: {}, Code: {}, Checksum: {}'.format(imcp_type, code, checksum))
                print (TAB_3 + 'Data: {}'.format(data))

            elif proto == 6:
                (src_port , dest_port , sequence , acknowledgement , flag_urg , flag_ack , flag_psh , flag_rst , flag_syn , flag_fin , data) = tcp_segment(data)
                print (TAB_2 + 'TCP Segment:')
                print (TAB_3 + 'Source Port: {}, Destination Port: {}, Sequence: {}, Acknowledgement: {}'.format(src_port, dest_port, sequence, acknowledgement))
                print (TAB_3 + 'Flags:')
                print (TAB_4 + 'URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print (TAB_3 + 'Data: {}'.format(data))
                print (format_multi_line(DATA_TAB_3, data))

            elif proto == 17:
                print (TAB_2 + 'UDP Segment:')
                print (TAB_3 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, len(data)))
                print (TAB_3 + 'Data: {}'.format(data))
                print (format_multi_line(DATA_TAB_3, data))
            else:
                print (TAB_2 + 'Data: {}'.format(data))
                print (format_multi_line(DATA_TAB_3, data))


def ethernet_frame(data):
    """
    Build an Ethernet frame
    """
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def unpack_ip(data):
    version_ihl = data[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, ihl, iph_length, ttl, proto, ipv4(src), ipv4(target), data[ihl:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def imcp_packet(data):
    imcp_tpye , code , checksum = struct.unpack('! B B H', data[:4])
    return imcp_tpye, code, checksum, data[4:]

def tcp_segment(data):
    (src_port , dest_port , sequence , acknowledgement , offset_reserved) = struct.unpack('! H H L L H', data[:14]) 
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 32) >> 4
    flag_psh = (offset_reserved_flags & 32) >> 3
    flag_rst = (offset_reserved_flags & 32) >> 2
    flag_syn = (offset_reserved_flags & 32) >> 1
    flag_fin = (offset_reserved_flags & 32) & 1
    return src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

     

main()