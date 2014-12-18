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

void callback_raw_packet (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user. */
    (void) user;

    /* Print the packet. */
    for (size_t i = 0; i < header->caplen; ++i)
    {
        /* Print 16 bytes per line. */
        if (! (i % 16))
            printf ("\n");
        printf ("%.2x ", bytes[i]);
    }
    /* Separate packets. */
    printf ("\n\n");
}

void callback_info_concise (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    (void) user; (void) header; (void) bytes;
}

void callback_info_synthetic (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    (void) user; (void) header; (void) bytes;
}

void callback_info_complete (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    (void) user; (void) header; (void) bytes;
}
