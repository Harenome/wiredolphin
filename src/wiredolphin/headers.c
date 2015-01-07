/**
 * \file headers.c
 * \brief Headers.
 * \author RAZANAJATO RANAIVOARIVONY Harenome
 * \date 2014
 * \copyright WTFPLv2
 */
/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://www.wtfpl.net/ for more details.
 */

#include "wiredolphin/headers.h"

////////////////////////////////////////////////////////////////////////////////
// Static utilities.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print the ethernet protocol ID.
 * \param stream Output stream.
 * \param protocol_id Protocol ID.
 */
static inline void __header_ethernet_print_protocol (FILE * stream,
        uint16_t protocol_id);

/**
 * \brief Print a MAC address.
 * \param stream Output stream.
 * \param address MAC address.
 */
static inline void __header_ethernet_print_mac (FILE * stream,
        const u_int8_t address[ETH_ALEN]);

////////////////////////////////////////////////////////////////////////////////
// Ethernet frames.
////////////////////////////////////////////////////////////////////////////////

void header_ethernet_print_complete (FILE * const stream,
        const u_char * const bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;

    fprintf (stream, "Ethernet header\n===============\n");

    /* Print the source. */
    fprintf (stream, "%-12s\t", "Source:");
    __header_ethernet_print_mac (stream, header->ether_shost);
    fprintf (stream, "\n");

    /* Print the destination. */
    fprintf (stream, "%-12s\t", "Destination:");
    __header_ethernet_print_mac (stream, header->ether_dhost);
    fprintf (stream, "\n");

    /* Print the packet type. */
    fprintf (stream, "%-12s\t", "Packet type:");
    __header_ethernet_print_protocol (stream, ntohs (header->ether_type));
    fprintf (stream, "\n");

    fprintf (stream, "\n");
}

void header_ethernet_print_synthetic (FILE * const stream,
        const u_char * const bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;

    /* <source> -> <destination>, <packet type> */
    __header_ethernet_print_mac (stream, header->ether_shost);
    fprintf (stream, " -> ");
    __header_ethernet_print_mac (stream, header->ether_dhost);
    fprintf (stream, ", ");
    __header_ethernet_print_protocol (stream, ntohs (header->ether_type));
    fprintf (stream, "\n");
}

uint16_t header_ethernet_packet_type (const u_char * const bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;
    return ntohs (header->ether_type);
}

const u_char * header_ethernet_data (const u_char * bytes)
{
    return bytes + sizeof (struct ether_header);
}

////////////////////////////////////////////////////////////////////////////////
// Misc.
////////////////////////////////////////////////////////////////////////////////

void __header_ethernet_print_protocol (FILE * const stream,
        uint16_t protocol_id)
{
    const char * protocol_string = "";
    switch (protocol_id)
    {
        case ETHERTYPE_PUP:
            protocol_string = "Xerox PUP"; break;
        case ETHERTYPE_SPRITE:
            protocol_string = "Sprite"; break;
        case ETHERTYPE_IP:
            protocol_string = "IP"; break;
        case ETHERTYPE_ARP:
            protocol_string = "ARP"; break;
        case ETHERTYPE_REVARP:
            protocol_string = "Reverse ARP"; break;
        case ETHERTYPE_AT:
            protocol_string = "AppleTalk Protocol"; break;
        case ETHERTYPE_AARP:
            protocol_string = "AppleTalk ARP"; break;
        case ETHERTYPE_VLAN:
            protocol_string = "IEEE 802.1Q VLAN tagging"; break;
        case ETHERTYPE_IPX:
            protocol_string = "IPX"; break;
        case ETHERTYPE_IPV6:
            protocol_string = "IPv6"; break;
        case ETHERTYPE_LOOPBACK:
            protocol_string = "Test"; break;
        default:
            protocol_string = "Unknown"; break;
    }
    fprintf (stream, "%s", protocol_string);
}

void __header_ethernet_print_mac (FILE * const stream,
        const u_int8_t address[ETH_ALEN])
{
    /* Print the subparts of the address, separated by colons. */
    for (size_t i = 0; i < ETH_ALEN; ++i)
        fprintf (stream, "%.2x%c", address[i], i < ETH_ALEN - 1 ? ':' : '\0');
}
