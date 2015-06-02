import socket
import struct
import os

def analyze_ethernet_packet(data):
    ethernet_header = struct.unpack("!6s6sh",data[:14])
    dstaddr = ethernet_header[0]
    srcaddr = ethernet_header[1]
    if ethernet_header[2] == 0x0800:
        packettype = "IP"
        packet = analyze_ip_packet(data[14:])
    elif ethernet_header[2] == 0x0806:
        packettype = "ARP"
        packet = analyze_arp_packet(data[14:])
    else:
        packettype = ""
        packet = ()
    return (dstaddr,srcaddr,packettype,packet)

def analyze_ip_packet(data):
    ip_header = struct.unpack("!BBHHHBBHBBBBBBBB",data[:20])
    ip_version = ip_header[0]/16
    ip_header_len = 4*(ip_header[0]%16)
    ip_srv_type = ip_header[1]
    ip_packet_len = ip_header[2]
    ip_id = ip_header[3]
    ip_flag = ip_header[4]/8192
    ip_offset = ip_header[4]%8192
    ip_TTL = ip_header[5]
    if ip_header[6] == 0x1:
        ip_protocol = "ICMP"
        packet = analyze_icmp_packet(data[ip_header_len:])
    elif ip_header[6] == 0x6:
        ip_protocol = "TCP"
        packet = analyze_tcp_packet(data[ip_header_len:])
    elif ip_header[6] == 0x11:
        ip_protocol = "UDP"
        packet = analyze_udp_packet(data[ip_header_len:])
    else:
        ip_protocol = ""
        packet = ()
    ip_checksum = ip_header[7]
    ip_src_addr = "%u.%u.%u.%u"%(ip_header[8],ip_header[9],ip_header[10],ip_header[11])
    ip_dst_addr = "%u.%u.%u.%u"%(ip_header[12],ip_header[13],ip_header[14],ip_header[15])
    return (ip_version,ip_header_len,ip_srv_type,ip_packet_len,
            ip_id,ip_flag,ip_offset,ip_TTL,
            ip_protocol,ip_checksum,ip_src_addr,ip_dst_addr,
            packet)

def analyze_icmp_packet(data):
    icmp_header = struct.unpack("!BBH",data[:4])
    icmp_type = icmp_header[0]
    icmp_code = icmp_header[1]
    icmp_checksum = icmp_header[2]
    if icmp_type == 0x0:
        icmp_type = "Echo Reply"
        icmp_code = ""
        icmp_id = struct.unpack("!H",data[4:6])
        icmp_sq_num = struct.unpack("!H",data[6:8])
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_id,icmp_sq_num,icmp_data)
    elif icmp_type == 0x3:
        icmp_type = "Destination Unreachable"
        if icmp_code == 0:
            icmp_code = "net unreachable"
        elif icmp_code == 1:
            icmp_code = "host unreachable"
        elif icmp_code == 2:
            icmp_code = "protocol unreachable"
        elif icmp_code == 3:
            icmp_code = "port unreachable"
        elif icmp_code == 4:
            icmp_code = "fragmentation needed and DF set"
        elif icmp_code == 5:
            icmp_code = "source route failed"
        else:
            icmp_code =""
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_data)
    elif icmp_type == 0x4:
        icmp_type = "Source Quench"
        icmp_code = ""
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_data)
    elif icmp_type == 0x5:
        icmp_type = "Redirect"
        if icmp_code == 0:
            icmp_code = "Redirect datagrams for the Network"
        elif icmp_code == 1:
            icmp_code = "Redirect datagrams for the Host"
        elif icmp_code == 2:
            icmp_code = "Redirect datagrams for the Type of Serivce and Network"
        elif icmp_code == 3:
            icmp_code = "Redirect datagrams for the Type of Service and Host"
        else:
            icmp_code = ""
        addr = struct.unpack("!BBBB",data[4:8])
        icmp_gateway_addr = "%u.%u.%u.%u"%(addr[0],addr[1],addr[2],addr[3])
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_gateway_addr,icmp_data)
    elif icmp_type == 0x8:
        icmp_type = "Echo"
        icmp_code = ""
        icmp_id = struct.unpack("!H",data[4:6])
        icmp_sq_num = struct.unpack("!H",data[6:8])
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_id,icmp_sq_num,icmp_data)
    elif icmp_type == 0x11:
        icmp_type = "Time Exceeded"
        if icmp_code == 0x0:
            icmp_code = "time to live exceeded in transit"
        elif icmp_code == 0x1:
            icmp_code = "fragment reassembly time exceeded"
        else:
            icmp_code = ""
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_data)
    elif icmp_type == 0x12:
        icmp_type = "Parameter Problem"
        icmp_code = "pointer indicates the error"
        icmp_pointer = struct.unpack("!B",data[4])
        icmp_data = data[8:]
        return (icmp_type,icmp_code,icmp_pointer,icmp_data)
    elif icmp_type == 0x13:
        icmp_type = "Timestamp"
        icmp_code = ""
        icmp_id = struct.unpack("!H",data[4:6])
        icmp_sq_num = struct.unpack("!H",data[6:8])
        icmp_org_timestamp = struct.unpack("!L",data[8:12])
        icmp_rsv_timestamp = struct.unpack("!L",data[12:16])
        icmp_trm_timestamp = struct.unpack("!L",data[16:20])
        return (icmp_type,icmp_code,icmp_id,icmp_sq_num,
                icmp_org_timestamp,icmp_rsv_timestamp,icmp_trm_timestamp)
    elif icmp_type == 0x14:
        icmp_type = "Timestamp Reply"
        icmp_code = ""
        icmp_id = struct.unpack("!H",data[4:6])
        icmp_sq_num = struct.unpack("!H",data[6:8])
        icmp_org_timestamp = struct.unpack("!L",data[8:12])
        icmp_rsv_timestamp = struct.unpack("!L",data[12:16])
        icmp_trm_timestamp = struct.unpack("!L",data[16:20])
        return (icmp_type,icmp_code,icmp_id,icmp_sq_num,
                icmp_org_timestamp,icmp_rsv_timestamp,icmp_trm_timestamp)
    elif icmp_type == 0x15:
        icmp_type = "Information Request"
        icmp_code = ""
        icmp_id = struct.unpack("!H",data[4:6])
        icmp_sq_num = struct.unpack("!H",data[6:8])
        return (icmp_type,icmp_code,icmp_id,icmp_sq_num)
    elif icmp_type == 0x16:
        icmp_type = "Information Reply"
        icmp_code = ""
        icmp_id = struct.unpack("!H",data[4:6])
        icmp_sq_num = struct.unpack("!H",data[6:8])
        return (icmp_type,icmp_code,icmp_id,icmp_sq_num)
    else:
        icmp_type = ""
        return (icmp_type)

def analyze_tcp_packet(data):
    tcp_header = struct.unpack("!HHLLHHHH",data[:20])
    tcp_src_port = tcp_header[0]
    tcp_dst_port = tcp_header[1]
    tcp_sqc_num = tcp_header[2]
    tcp_ack_num = tcp_header[3]
    tcp_header_len = 4*(tcp_header[4]/4096)
    tcp_URG = (tcp_header[4]/32)%2 == 1
    tcp_ACK = (tcp_header[4]/16)%2 == 1
    tcp_PSH = (tcp_header[4]/8)%2 == 1
    tcp_RST = (tcp_header[4]/4)%2 == 1
    tcp_SYN = (tcp_header[4]/2)%2 == 1
    tcp_FIN = (tcp_header[4])%2 == 1
    tcp_window = tcp_header[5]
    tcp_checksum = tcp_header[6]
    tcp_urgent = tcp_header[7]
    tcp_data = data[tcp_header_len:]
    return (tcp_src_port,tcp_dst_port,tcp_sqc_num,tcp_ack_num,
            tcp_header_len,tcp_URG,tcp_ACK,tcp_PSH,
            tcp_RST,tcp_SYN,tcp_FIN,tcp_window,
            tcp_checksum,tcp_urgent,tcp_data)

def analyze_udp_packet(data):
    udp_header = struct.unpack("!HHHH",data[:8])
    udp_src_port = udp_header[0]
    udp_dst_port = udp_header[1]
    udp_packet_len = udp_header[2]
    udp_checksum = udp_header[3]
    udp_data = data[8:]
    return (udp_src_port,udp_dst_port,udp_packet_len,udp_checksum,
            udp_data)

def analyze_arp_packet(data):
    arp_header = struct.unpack("!HHBBH",data[:8])
    if arp_header[0] == 0x1:
        arp_hdw_type = "Ethernet"
    else:
        arp_hdw_type = ""
    if arp_header[1] == 0x800:
        arp_protocol_type = "IP"
    else:
        arp_protocol_type = ""
    arp_hdw_addr_len = arp_header[2]
    arp_protocol_addr_len = arp_header[3]
    arp_opcode = arp_header[4]
    b = 8
    arp_src_hdw_addr = data[b:b+arp_hdw_addr_len]
    b += arp_hdw_addr_len
    addr = struct.unpack("!BBBB",data[b:b+4])
    arp_src_protocol_addr = "%u.%u.%u.%u"%(addr[0],addr[1],addr[2],addr[3])
    b += 4
    arp_dst_hdw_addr = data[b:b+arp_hdw_addr_len]
    b += arp_hdw_addr_len
    addr = struct.unpack("!BBBB",data[b:b+4])
    arp_dst_protocol_addr = "%u.%u.%u.%u"%(addr[0],addr[1],addr[2],addr[3])
    return (arp_hdw_type,arp_protocol_type,arp_hdw_addr_len,arp_protocol_addr_len,arp_opcode,
            arp_src_hdw_addr,arp_src_protocol_addr,arp_dst_hdw_addr,arp_dst_protocol_addr)

def print_packet_info(info):
    print "Ethernet: "
    print "  Destination Address: %s"%info[0].encode("hex")
    print "  Source Address: %s"%info[1].encode("hex")
    if info[2] == "IP":
        print "IP:"
        print "  Version: IPv%d"%info[3][0]
        print "  Packet Length: %d"%info[3][3]
        print "  Identifier: %x"%info[3][4]
        print "  Time to Live: %d"%info[3][7]
        print "  Protocol: %s"%info[3][8]
        print "  Source IP: %s"%info[3][10]
        print "  Destination IP: %s"%info[3][11]
        if info[3][8] == "ICMP":
            print "ICMP:"
            if info[3][12][0] == "Echo Reply":
                print "  Type: %s"%info[3][12][0]
                print "  Data: %s"%split_hex(info[3][12][4].encode("hex"),16)
            elif info[3][12][0] == "Destination Unreachable":
                print "  Type: %s"%info[3][12][0]
                print "  Code: %s"%info[3][12][1]
                print "  Data: %s"%split_hex(info[3][12][2].encode("hex"),16)
            elif info[3][12][0] == "Source Quench":
                print "  Type: %s"%info[3][12][0]
                print "  Data: %s"%split_hex(info[3][12][2].encode("hex"),16)
            elif info[3][12][0] == "Redirect":
                print "  Type: %s"%info[3][12][0]
                print "  Code: %s"%info[3][12][1]
                print "  Gateway Address: %s"%info[3][12][2]
                print "  Data: %s"%split_hex(info[3][12][3].encode("hex"),16)
            elif info[3][12][0] == "Echo":
                print "  Type: %s"%info[3][12][0]
                print "  Data: %s"%split_hex(info[3][12][4].encode("hex"),16)
            elif info[3][12][0] == "Time Exceeded":
                print "  Type: %s"%info[3][12][0]
                print "  Code: %s"%info[3][12][1]
                print "  Data: %s"%split_hex(info[3][12][2].encode("hex"),16)
            elif info[3][12][0] == "Parameter Problem":
                print "  Type: %s"%info[3][12][0]
                print "  Data: %s"%split_hex(info[3][12][3].encode("hex"),16)
            elif info[3][12][0] == "Timestamp":
                print "  Type: %s"%info[3][12][0]
                print "  Originate Timestamp: %u"%info[3][12][4]
                print "  Receive Timestamp: %u"%info[3][12][5]
                print "  Transmit Timestamp: %u"%info[3][12][6]
            elif info[3][12][0] == "Timestamp Reply":
                print "  Type: %s"%info[3][12][0]
                print "  Originate Timestamp: %u"%info[3][12][4]
                print "  Receive Timestamp: %u"%info[3][12][5]
                print "  Transmit Timestamp: %u"%info[3][12][6]
            elif info[3][12][0] == "Information Request":
                print "  Type: %s"%info[3][12][0]
            elif info[3][12][0] == "Information Reply":
                print "  Type: %s"%info[3][12][0]
        elif info[3][8] == "TCP":
            print "TCP:"
            print "  Source Port: %u"%info[3][12][0]
            print "  Destination Port: %u"%info[3][12][1]
            print "  TCP URG:",info[3][12][5]
            print "  TCP ACK:",info[3][12][6]
            print "  TCP PSH:",info[3][12][7]
            print "  TCP RST:",info[3][12][8]
            print "  TCP SYN:",info[3][12][9]
            print "  TCP FIN:",info[3][12][10]
            print "  Data:"
            print info[3][12][14]
        elif info[3][8] == "UDP":
            print "UDP:"
            print "  Source Port: %u"%info[3][12][0]
            print "  Destination Port: %u"%info[3][12][1]
            print "  Packet Length: %u"%info[3][12][2]
            print "  Data:"
            print split_hex(info[3][12][4].encode("hex"),16)
    elif info[2] == "ARP":
        print "ARP"
        print "  Hardware Type: %s"%info[3][0]
        print "  Protocol Type: %s"%info[3][1]
        print "  Hardware Address Length: %u"%info[3][2]
        print "  Protocol Address Length: %u"%info[3][3]
        print "  Opcode: %x"%info[3][4]
        print "  Source Hardware Address: %s"%info[3][5].encode("hex")
        print "  Source Protocol Address: %s"%info[3][6]
        print "  Destination Hardware Address: %s"%info[3][7].encode("hex")
        print "  Destination Protocol Address: %s"%info[3][8]
    else:
        print "Unknown Network Type"
        
    print

def split_hex(s,n):
    r = ""
    while len(s) > 0:
        if len(s) <= n:
            r = r+s+"\n"
            break
        r = r+s[:n]+"\n"
        s = s[n:]
    return r

def main():
    sniffer_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    while True:
        data = sniffer_socket.recv(20000)
        info = analyze_ethernet_packet(data) 
        print_packet_info(info)

main()
