# %%
#######################################
def structparse_ethernet_header(bytes_string: bytes):
    """Takes a given bytes string of a packet and returns the Ethernet destination and source MAC addresses along with the Ethernet Type within that packet.

    Examples:
        >>> from scapy.all import *\n
        >>> icmp_pcap = rdpcap('icmp.pcap')\n
        >>> firstpacket = icmp_pcap[0]\n
        >>> thebytes_firstpacket = firstpacket.__bytes__()\n
        >>> structparse_ethernet_header(thebytes_firstpacket[:14])\n
        {'eth_dst': '00:0d:b9:27:07:80', 'eth_src': '00:0c:29:25:6c:15', 'eth_type': '0x800'}
        
    References:
        # Here we did some research on an "unsigned integer" or "uint" versus an "int".  The struct reference table indicates that "H" is used for 'unsigned' integers that are 2 bytes in size (positive only, 0 to 65535) and that "h" is used for 'signed' integers (negative and positive, -32,768 to 32,767)\n
        https://stackoverflow.com/questions/3724242/what-is-the-difference-between-int-and-uint-long-and-ulong\n
        
        # Inserting a colon for every 2 characters in the MAC address:\n
        https://stackoverflow.com/questions/3258573/pythonic-way-to-insert-every-2-elements-in-a-string\n

    Args:
        bytes_string (bytes): Reference a bytes string representation of a packet.
        
    Returns:
        dict: Returns a dictionary.
    """
    import struct
    import binascii
    first_14_bytes = bytes_string[:14]
#
    # Here we specify 'network byte order' with "!" ( network byte order is Big Endian, so we could have also used ">" ), then we get the first 6 bytes as a 'str' (6s) for the destination MAC, the next 6 bytes as 'str' (6s) for the source MAC, and then 2 bytes as uint (unsigned integer) represented by "H"
    eth_dst, eth_src, eth_type = struct.unpack('!6s6sH', first_14_bytes)
#
    # Here we change the format of the hex bytes, decode it to be a str, and add a ':' after ever two characters
    eth_dst = ':'.join( binascii.b2a_hex(eth_dst).decode()[i:i+2] for i in range(0, len(binascii.b2a_hex(eth_dst).decode()), 2))
    eth_src = ':'.join( binascii.b2a_hex(eth_src).decode()[i:i+2] for i in range(0, len(binascii.b2a_hex(eth_src).decode()), 2))
#
    eth_type = hex(eth_type)
#
    results_dict = {}
    results_dict['eth_dst'] = eth_dst
    results_dict['eth_src'] = eth_src
    results_dict['eth_type'] = eth_type
    return results_dict

