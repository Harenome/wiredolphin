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

static inline void __raw_packet_print (const u_char * bytes, size_t size);

void __raw_packet_print (const u_char * bytes, size_t size)
{
    /* Print the packet. */
    for (size_t i = 0; i < size; ++i)
    {
        /* Print 16 bytes per line. */
        if (! (i % 16) && i)
            printf ("\n");
        printf ("%.2x ", bytes[i]);
    }

    printf ("\n\n");
}

void callback_raw_packet (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user. */
    (void) user;

    /* Print the packet. */
    __raw_packet_print (bytes, header->caplen);
}

void callback_info_concise (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user and header. */
    (void) user; (void) header;

    header_ethernet_print_synthetic (bytes);
}

void callback_info_synthetic (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user and header. */
    (void) user; (void) header;

    header_ethernet_print_synthetic (bytes);
}

void callback_info_complete (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user. */
    (void) user;

    __raw_packet_print (bytes, header->caplen);
    header_ethernet_print_complete (bytes);
}
