# %%
#######################################
def structparse_ip_header_embedded_protocol(bytes_string: bytes):
    """Takes a given bytes string of a packet and returns information found in the IP header about the embedded protocol at the next level of encapsulation.

    Examples:
        >>> from scapy.all import *\n
        >>> icmp_pcap = rdpcap('icmp.pcap')\n
        >>> firstpacket = icmp_pcap[0]\n
        >>> thebytes_firstpacket = firstpacket.__bytes__()\n
        >>> structparse_ip_header_embedded_protocol(thebytes_firstpacket)\n
        {'embedded_protocol': 'ICMP'}

    Args:
        bytes_string (bytes): Reference a bytes string representation of a packet.
    
    Returns:
        dict: Returns a dictionary.
    """
    import struct
#
    # We define a lookup table for embedded protocols we want to specify
    embedded_protocols_dict = {17:'UDP', 6:'TCP', 1:'ICMP'}
#
    # We skip the first 14 bytes which are the Ethernet header
    ip_layer_plus = bytes_string[14:]
#
    # This uses 'network byte order' (represented by '!') which is Big Endian (so we could have use '>' instead of '!'); we then ignore the first 9 bytes of the IP header using '9x', and process the next 1 byte as an unsigned integer using 'B'
    # - we use the [0] because the '.unpack()' method always returns a tuple, even when a single element is present, and in this case we just want a single element
    embed_protocol_num = ( struct.unpack('!9xB', ip_layer_plus[:10]) )[0]
#
    # Here we define a fallback answer in case the "protocol number" is not one we specified in our "embedded_protocols_dict"
    embed_protocol_num_notfound = f'Undefined Protocol, protocol number: {embed_protocol_num}'
#
    # We do a lookup of the 'embed_protocol_num' that we parsed out of the bytes, and specify the fallback value as a catch-all
    proto_name = embedded_protocols_dict.get(embed_protocol_num, embed_protocol_num_notfound)
# 
    results = {}
    results['embedded_protocol'] = proto_name
    return results

