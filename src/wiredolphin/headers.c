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
 * \param protocol_id Protocol ID.
 */
static inline void __header_ethernet_print_protocol (uint16_t protocol_id);

/**
 * \brief Print a MAC address.
 * \param address MAC address.
 */
static inline void __header_ethernet_print_mac (const u_int8_t address[ETH_ALEN]);

////////////////////////////////////////////////////////////////////////////////
// Ethernet frames.
////////////////////////////////////////////////////////////////////////////////

void header_ethernet_print_complete (const u_char * bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;

    printf ("Ethernet header\n===============\n");
    printf ("%-12s\t", "Destination:");
    __header_ethernet_print_mac (header->ether_dhost);
    printf ("\n");

    printf ("%-12s\t", "Source:");
    __header_ethernet_print_mac (header->ether_shost);
    printf ("\n");

    printf ("%-12s\t", "Packet type:");
    __header_ethernet_print_protocol (ntohs (header->ether_type));
    printf ("\n\n");
}

void header_ethernet_print_synthetic (const u_char * bytes)
{
    const struct ether_header * header = (const struct ether_header *) bytes;
    __header_ethernet_print_mac (header->ether_dhost);
    printf (" -> ");
    __header_ethernet_print_mac (header->ether_shost);
    printf (", ");
    __header_ethernet_print_protocol (ntohs (header->ether_type));
    printf ("\n");
}

uint16_t header_ethernet_packet_type (const u_char * bytes)
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

void __header_ethernet_print_protocol (uint16_t protocol_id)
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
    printf ("%s", protocol_string);
}

void __header_ethernet_print_mac (const u_int8_t address[ETH_ALEN])
{
    for (size_t i = 0; i < ETH_ALEN; ++i)
        printf ("%.2x%c", address[i], i < ETH_ALEN - 1 ? ':' : '\0');
}
