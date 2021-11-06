# %%
#######################################
def structparse_icmp_header_message(bytes_string: bytes):
    """Takes a given bytes string of a packet and returns the ICMP message found in the ICMP header.

    Examples:
        >>> from scapy.all import *\n
        >>> icmp_pcap = rdpcap('icmp.pcap')\n
        
        >>> firstpacket = icmp_pcap[0]\n
        >>> thebytes_firstpacket = firstpacket.__bytes__()\n
        
        >>> structparse_icmp_header_message(thebytes_firstpacket)\n
        {'icmp_message': 'Echo Request'}

        >>> [print(structparse_icmp_header_message(p.__bytes__())) for p in icmp_pcap][0]\n
        {'icmp_message': 'Echo Request'}\n
        {'icmp_message': 'Echo Reply'}\n
        {'icmp_message': 'Echo Request'}\n
        {'icmp_message': 'Echo Reply'}\n
        {'icmp_message': 'Echo Request'}\n
        {'icmp_message': 'Echo Reply'}\n
        {'icmp_message': 'Echo Request'}\n
        {'icmp_message': 'Echo Reply'}\n
        {'icmp_message': 'Echo Request'}\n
        {'icmp_message': 'Echo Reply'}\n
        {'icmp_message': 'Echo Request'}\n
        {'icmp_message': 'Echo Reply'}\n

    References:
        # Used this cheat sheet to create the ICMP Type/Code dictionary:\n
        https://www.sans.org/posters/tcp-ip-and-tcpdump/\n

        # Got the idea for the double .get() method for the nested dictionary here:\n
        https://stackoverflow.com/questions/25833613/safe-method-to-get-value-of-nested-dictionary\n
        

    Args:
        bytes_string (bytes): Reference a bytes string representation of a packet.
    
    Returns:
        dict: Returns a dictionary.
    """
    import struct
#   
    # Skip the 14 byte Ethernet header
    ip_layer_plus = bytes_string[14:]
#   
    # Assumes IP header with no options, add checks for that later on
    icmp_layer_plus = ip_layer_plus[20:]
#
    # We unpack the 8 bytes of the ICMP header, using 'network byte order' (represented by '!') which is Big Endian (so we could have use '>' instead of '!')
    icmp_type, icmp_code, icmp_chksum, icmp_offset4, icmp_offset6 = struct.unpack('!BBHHH', icmp_layer_plus[:8])
#
    # https://www.sans.org/posters/tcp-ip-and-tcpdump/
    icmp_type_code_dict = {
        0: {0: 'Echo Reply'},
        3: {0: 'Network Unreachable',
            1: 'Host Unreachable',
            2: 'Protocol Unreachable',
            3: 'Port Unreachable',
            4: 'Fragmentation Required',
            5: 'Source Route Failed',
            6: 'Dest. Network Unknown',
            7: 'Dest. Host Unknown',
            8: 'Source Host Isolated',
            9: 'Net Administratively Prohibited',
            10: 'Host Administratively Prohibited',
            11: 'Network unreachable for TOS',
            12: 'Host unreachable for TOS',
            13: 'Communication Admin. Prohibited'},
        4: {0: 'Source quench'},
        5: {0: 'Network Redirect',
            1: 'Host Redirect',
            2: 'TOS & Network Redirect',
            3: 'TOS & Host Redirect'},
        8: {0: 'Echo Request'},
        9: {0: 'Router Advertisement'},
        11: {0: 'Time to live exceeded in transit',
            1: 'Fragment REassembly time exceeded'},
        12: {0: 'Parameter Prob. Pointer indicated time error',
            1: 'Missing a required option',
            2: 'Bad length'},
        13: {0: 'Timestamp'},
        14: {0: 'Timestamp Reply'},
        15: {0: 'Information Request'},
        16: {0: 'Information Reply'},
        17: {0: 'Address Mask Request'},
        18: {0: 'Address Mask Reply'},
        30: {0: 'Traceroute'}
    }
#
    # https://stackoverflow.com/questions/25833613/safe-method-to-get-value-of-nested-dictionary
    # icmp_type_code_dict[icmp_type][icmp_code]
    icmp_message = icmp_type_code_dict.get(icmp_type, f'Type number not found: {icmp_type}').get(icmp_code, f'Code number not found: {icmp_code}')
#
    results = {}
    results['icmp_message'] = icmp_message
    return results

