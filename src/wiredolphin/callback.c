/**
 * \file callback.c
 * \brief Callbacks.
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

#include "wiredolphin/callback.h"

////////////////////////////////////////////////////////////////////////////////
// Static utilities.
////////////////////////////////////////////////////////////////////////////////

static inline void __raw_packet_print (FILE * stream,
        const u_char * bytes, size_t size);

////////////////////////////////////////////////////////////////////////////////
// Callbacks.
////////////////////////////////////////////////////////////////////////////////

void callback_raw_packet (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user. */
    (void) user;

    /* Print the packet. */
    __raw_packet_print (stdout, bytes, header->caplen);
}

void callback_info_concise (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user and header. */
    (void) user; (void) header;

    header_ethernet_print_synthetic (stdout, bytes);
}

void callback_info_synthetic (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user and header. */
    (void) user; (void) header;

    header_ethernet_print_synthetic (stdout, bytes);
}

void callback_info_complete (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user. */
    (void) user;

    /* Print the raw packet. */
    __raw_packet_print (stdout, bytes, header->caplen);

    /* Print the ethernet header. */
    header_ethernet_print_complete (stdout, bytes);

    /* Print the underlying packet. */
    uint16_t packet_type = header_ethernet_packet_type (bytes);
    bytes = header_ethernet_data (bytes);

    switch (packet_type)
    {
        case ETHERTYPE_IP:
            header_ipv4_print_complete (stdout, bytes);
            bytes = header_ipv4_data (bytes);
            break;
        case ETHERTYPE_ARP:
            header_arp_print_complete (stdout, bytes);
            break;
        case ETHERTYPE_IPV6:
            break;
        default:
            break;
    }
}

////////////////////////////////////////////////////////////////////////////////
// Misc.
////////////////////////////////////////////////////////////////////////////////

void __raw_packet_print (FILE * const stream, const u_char * const bytes,
        size_t size)
{
    /* Print the packet. */
    for (size_t i = 0; i < size; ++i)
    {
        /* Print 16 bytes per line. */
        if (! (i % 16) && i)
            fprintf (stream, "\n");
        fprintf (stream, "%.2x ", bytes[i]);
    }

    fprintf (stream, "\n\n");
}

