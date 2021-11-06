def structparse_ip_header_info(bytes_string: bytes):
    """Takes a given bytes string of a packet and returns information found in the IP header such as the IP Version, IP Header Length, and if IP Options are present.

    Examples:
        >>> from scapy.all import *\n
        >>> icmp_pcap = rdpcap('icmp.pcap')\n
        >>> firstpacket = icmp_pcap[0]\n
        >>> thebytes_firstpacket = firstpacket.__bytes__()\n
        >>> structparse_ip_header_len(thebytes_firstpacket)\n
        {'ip_version': 4, 'ip_header_len': 20, 'info': 'IHL = 20 bytes, No IP Options Present'}

    References:
        https://docs.python.org/3/library/struct.html

    Args:
        bytes_string (bytes): Reference a bytes string representation of a packet.
    
    Returns:
        dict: Returns a dictionary.
    """
    import struct
#
    # This is an alternate way to get to the data we want, but we want to demo the usage of struct
    # - ip_layer_plus = bytes_string[14:]
    # - ip_byte0 = ip_layer_plus[0]
#
    # This uses 'network byte order' (represented by '!') which is Big Endian (so we could have use '>' instead of '!'); we then ignore the first 14 bytes (which is the Ethernet header) using '14x', and process the next 1 byte as an unsigned integer using 'B'
    # - we use the [0] because the '.unpack()' method always returns a tuple, even when a single element is present, and in this case we just want a single element
    ip_byte0 = ( struct.unpack('!14xB', bytes_string[:15]) )[0]
     
    # Doing a 'bit shift' of 4 bits to the right, pushing the most significant nibble to the right, and pushing the least significant nibble "over the cliff".  In other words, all that remains of our original 8 bits are the 4 left-most bits (the right-most 4 bits were pushed off of the cliff on the right side when we did the bit shift to the right)
    ip_version = ip_byte0 >> 4
    # Using the Bitwise AND operator "&"
    ip_header_len = (ip_byte0 & 15) * 4
#  
    if ip_header_len < 20:
        some_info = "IHL is < 20 bytes, something is wrong"
    elif ip_header_len == 20:
        some_info = "IHL = 20 bytes, No IP Options Present"
    else:
        some_info = "IHL > 20 bytes, IP Options are Present"
#      
    results = {}
    results['ip_version'] = ip_version
    results['ip_header_len'] = ip_header_len
    results['info'] = some_info
    return results

