# %%
#######################################
def structparse_ip_header_addresses(bytes_string: bytes):
    """Takes a given bytes string of a packet and returns the Source and Destination IP Addresses found in the IP header.

    Examples:
        >>> from scapy.all import *\n
        >>> icmp_pcap = rdpcap('icmp.pcap')\n
        >>> firstpacket = icmp_pcap[0]\n
        >>> thebytes_firstpacket = firstpacket.__bytes__()\n
        >>> structparse_ip_header_addresses(thebytes_firstpacket)\n
        {'ip_src': '10.1.1.140', 'ip_dst': '8.8.8.8'}
        
    References:
        https://docs.python.org/3/library/struct.html

    Args:
        bytes_string (bytes): Reference a bytes string representation of a packet.
    
    Returns:
        dict: Returns a dictionary.
    """
    import struct
    import socket
#
    # We skip the first 14 bytes which are the Ethernet header
    ip_layer_plus = bytes_string[14:]
#
    # We use 'unpack' to get our correctly sized chunks from the bytes string and put them into our variables respectively (each variable will contain an 'unsigned long' int value -- https://docs.python.org/3/library/struct.html)
    # The Source IP begins as the 12th byte offset in the IP header
    # The Dest IP begins at the 16th byte offset in the IP header
    ip_src, ip_dst = struct.unpack('!12xLL', ip_layer_plus[:20])
#
    # Above we used struct.unpack to parse out the values and that translated those chunks into integers; however, 'socket.inet_ntoa()' expects "bytes", so we use .pack() to turn our respective chunks back into bytes and then let 'socket.inet_ntoa()' translate each value into the recognizable IP address format (as a string)
    ip_src_repacked = struct.pack('!L', ip_src)
    ip_dst_repacked = struct.pack('!L', ip_dst)
#
    ip_src_string = socket.inet_ntoa( ip_src_repacked )
    ip_dst_string = socket.inet_ntoa( ip_dst_repacked )
    results = {}
    results['ip_src'] = ip_src_string
    results['ip_dst'] = ip_dst_string
    return results

