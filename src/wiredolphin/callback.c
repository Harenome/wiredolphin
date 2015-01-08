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

/**
 * \brief Print a name and underline it.
 * \param stream Output stream.
 * \param name Name.
 */
static inline void __print_name (FILE * stream, const char * name);

/**
 * \brief Raw print a packet.
 * \param stream Output stream.
 * \param bytes Packet.
 * \param size Packet size.
 */
static inline void __raw_packet_print (FILE * stream,
        const u_char * bytes, size_t size);

/**
 * \brief Print bytes.
 * \param stream Output stream.
 * \param bytes First byte.
 * \param limit Byte following the last byte.
 */
static inline void __print_bytes (FILE * stream, const u_char * bytes,
        const u_char * limit);

/**
 * \brief Print the first line of the bytes.
 * \param stream Output stream.
 * \param bytes First byte.
 * \param limit Byte following the last byte.
 */
static inline void __print_bytes_start (FILE * stream, const u_char * bytes,
        const u_char * limit);

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
    (void) user;

    const u_char * limit = bytes + header->caplen;

    header_ethernet_print_synthetic (stdout, bytes);

    uint16_t packet_type = header_ethernet_packet_type (bytes);
    bytes = header_ethernet_data (bytes);

    struct in_addr src_addr;
    struct in_addr dest_addr;
    uint8_t next_protocol = 0;
    switch (packet_type)
    {
        case ETHERTYPE_IP:
            next_protocol = header_ipv4_protocol (bytes);
            src_addr = header_ipv4_src (bytes);
            dest_addr = header_ipv4_dest (bytes);
            bytes = header_ipv4_data (bytes);
            break;
        case ETHERTYPE_ARP:
            bytes = NULL;
            break;
        case ETHERTYPE_IPV6:
            break;
        default:
            break;
    }

    /* char * protocol = "??"; */
    /* u_int16_t source_port = 0; */
    /* u_int16_t dest_port = 0; */

    /* /1* Print the protocol header, if relevant. *1/ */
    /* if (bytes != NULL) */
    /* { */
    /*     switch (next_protocol) */
    /*     { */
    /*         case 1: /1* ICMP *1/ */
    /*             bytes = NULL; */
    /*             protocol = "ICMP"; */
    /*             break; */
    /*         case 6: /1* TCP *1/ */
    /*             source_port = header_tcp4_source_port (bytes); */
    /*             dest_port = header_tcp4_dest_port (bytes); */
    /*             bytes = header_tcp4_data (bytes); */
    /*             protocol = "TCP"; */
    /*             break; */
    /*         case 17: /1* UDP *1/ */
    /*             source_port = header_udp4_source_port (bytes); */
    /*             dest_port = header_udp4_dest_port (bytes); */
    /*             bytes = header_udp4_data (bytes); */
    /*             protocol = "UDP"; */
    /*             break; */
    /*         default: */
    /*             break; */
    /*     } */

    /*     fprintf (stdout, "; %s:%u -> %s:%u, %s", */
    /*             inet_ntoa (src_addr), source_port, */
    /*             inet_ntoa (dest_addr), dest_port, */
    /*             protocol); */
    /* } */
    char buffer_1[INET6_ADDRSTRLEN];
    char buffer_2[INET6_ADDRSTRLEN];
    char * protocol = "??";
    u_int16_t source_port = 0;
    u_int16_t dest_port = 0;

    /* Print the protocol header, if relevant. */
    if (bytes != NULL)
    {
        switch (next_protocol)
        {
            case 1: /* ICMP */
                bytes = NULL;
                protocol = "ICMP";
                break;
            case 6: /* TCP */
                source_port = header_tcp4_source_port (bytes);
                dest_port = header_tcp4_dest_port (bytes);
                bytes = header_tcp4_data (bytes);
                protocol = "TCP";
                break;
            case 17: /* UDP */
                source_port = header_udp4_source_port (bytes);
                dest_port = header_udp4_dest_port (bytes);
                bytes = header_udp4_data (bytes);
                protocol = "UDP";
                break;
            case 58:
                bytes = NULL;
                protocol = "ICMPv6";
                break;
            default:
                break;
        }

        if (packet_type == ETHERTYPE_IP)
        {
            inet_ntop (AF_INET, & src_addr, buffer_1, INET_ADDRSTRLEN);
            inet_ntop (AF_INET, & dest_addr, buffer_2, INET_ADDRSTRLEN);
        }
        else if (packet_type == ETHERTYPE_IPV6)
        {
            inet_ntop (AF_INET6, & src_addr, buffer_1, INET6_ADDRSTRLEN);
            inet_ntop (AF_INET6, & dest_addr, buffer_2, INET6_ADDRSTRLEN);
        }
        fprintf (stdout, "; %s:%u -> %s:%u, %s",
                buffer_1, source_port,
                buffer_2, dest_port,
                protocol);
    }

    if (bytes != NULL)
    {
        #define __application(port,name) \
            if (source_port == (port) || dest_port == (port)) \
            { \
                fprintf (stdout, "; %s: ", (name)); \
                __print_bytes_start (stdout, bytes, limit); \
            }

        __application (20, "FTP data");
        __application (21, "FTP control");
        __application (25, "SMTP");
        __application (67, "BOOTP");
        __application (68, "BOOTP");
        __application (80, "HTTP");
        __application (110, "POP");
        __application (143, "IMAP");
        __application (443, "HTTPS");
        __application (465, "Encrypted SMTP");
        __application (993, "Encrypted IMAP");
        __application (995, "Encrypted POP");

        #undef __application
    }

    fprintf (stdout, "\n\n");

}

void callback_info_synthetic (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    (void) user;

    const u_char * limit = bytes + header->caplen;

    fprintf (stdout,
            "*****************************************************************"
            "***************\n\n");

    header_ethernet_print_synthetic (stdout, bytes);
    fprintf (stdout, "\n");

    uint16_t packet_type = header_ethernet_packet_type (bytes);
    bytes = header_ethernet_data (bytes);

    struct in6_addr src_addr;
    struct in6_addr dest_addr;
    struct in_addr * addr_cheat;
    uint8_t next_protocol = 0;
    switch (packet_type)
    {
        case ETHERTYPE_IP:
            next_protocol = header_ipv4_protocol (bytes);
            addr_cheat = (struct in_addr *) & src_addr;
            * addr_cheat = header_ipv4_src (bytes);
            addr_cheat = (struct in_addr *) & dest_addr;
            * addr_cheat = header_ipv4_dest (bytes);
            bytes = header_ipv4_data (bytes);
            break;
        case ETHERTYPE_ARP:
            bytes = NULL;
            break;
        case ETHERTYPE_IPV6:
            next_protocol = header_ipv6_protocol (bytes);
            bytes = header_ipv6_data (bytes);
            break;
        default:
            break;
    }

    char buffer_1[INET6_ADDRSTRLEN];
    char buffer_2[INET6_ADDRSTRLEN];
    char * protocol = "??";
    u_int16_t source_port = 0;
    u_int16_t dest_port = 0;

    /* Print the protocol header, if relevant. */
    if (bytes != NULL)
    {
        switch (next_protocol)
        {
            case 1: /* ICMP */
                bytes = NULL;
                protocol = "ICMP";
                break;
            case 6: /* TCP */
                source_port = header_tcp4_source_port (bytes);
                dest_port = header_tcp4_dest_port (bytes);
                bytes = header_tcp4_data (bytes);
                protocol = "TCP";
                break;
            case 17: /* UDP */
                source_port = header_udp4_source_port (bytes);
                dest_port = header_udp4_dest_port (bytes);
                bytes = header_udp4_data (bytes);
                protocol = "UDP";
                break;
            case 58:
                bytes = NULL;
                protocol = "ICMPv6";
                break;
            default:
                break;
        }

        if (packet_type == ETHERTYPE_IP)
        {
            inet_ntop (AF_INET, & src_addr, buffer_1, INET_ADDRSTRLEN);
            inet_ntop (AF_INET, & dest_addr, buffer_2, INET_ADDRSTRLEN);
        }
        else if (packet_type == ETHERTYPE_IPV6)
        {
            inet_ntop (AF_INET6, & src_addr, buffer_1, INET6_ADDRSTRLEN);
            inet_ntop (AF_INET6, & dest_addr, buffer_2, INET6_ADDRSTRLEN);
        }
        fprintf (stdout, "%s:%u -> %s:%u, %s\n",
                buffer_1, source_port,
                buffer_2, dest_port,
                protocol);
    }

    if (bytes != NULL)
    {
        #define __application(port,name) \
            if (source_port == (port) || dest_port == (port)) \
            { \
                fprintf (stdout, "%s: ", (name)); \
                __print_bytes_start (stdout, bytes, limit); \
                fprintf (stdout, "\n"); \
            }

        __application (20, "FTP data");
        __application (21, "FTP control");
        __application (25, "SMTP");
        __application (67, "BOOTP");
        __application (68, "BOOTP");
        __application (80, "HTTP");
        __application (110, "POP");
        __application (143, "IMAP");
        __application (443, "HTTPS");
        __application (465, "Encrypted SMTP");
        __application (993, "Encrypted IMAP");
        __application (995, "Encrypted POP");

        #undef __application
    }

    fprintf (stdout, "\n");
}

void callback_info_complete (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes)
{
    /* Ignore user. */
    (void) user;

    const u_char * limit = bytes + header->caplen;

    fprintf (stdout,
            "*****************************************************************"
            "***************\n\n");

    /* Print the raw packet. */
    __raw_packet_print (stdout, bytes, header->caplen);

    /* Print the ethernet header. */
    header_ethernet_print_complete (stdout, bytes);
    fprintf (stdout, "\n");

    uint8_t next_protocol = 0;

    /* Print the underlying packet. */
    uint16_t packet_type = header_ethernet_packet_type (bytes);
    bytes = header_ethernet_data (bytes);
    switch (packet_type)
    {
        case ETHERTYPE_IP:
            next_protocol = header_ipv4_protocol (bytes);
            header_ipv4_print_complete (stdout, bytes);
            bytes = header_ipv4_data (bytes);
            break;
        case ETHERTYPE_ARP:
            header_arp_print_complete (stdout, bytes);
            bytes = NULL;
            break;
        case ETHERTYPE_IPV6:
            next_protocol = header_ipv6_protocol (bytes);
            header_ipv6_print_complete (stdout, bytes);
            bytes = header_ipv6_data (bytes);
            break;
        default:
            break;
    }

    u_int16_t source_port = 0;
    u_int16_t dest_port = 0;

    /* Print the protocol header, if relevant. */
    if (bytes != NULL)
        switch (next_protocol)
        {
            case 1: /* ICMP */
                header_icmp4_print_complete (stdout, bytes);
                bytes = NULL;
                break;
            case 6: /* TCP */
                header_tcp4_print_complete (stdout, bytes);
                source_port = header_tcp4_source_port (bytes);
                dest_port = header_tcp4_dest_port (bytes);
                bytes = header_tcp4_data (bytes);
                break;
            case 17: /* UDP */
                header_udp4_print_complete (stdout, bytes);
                source_port = header_udp4_source_port (bytes);
                dest_port = header_udp4_dest_port (bytes);
                bytes = header_udp4_data (bytes);
                break;
            case 58: /* ICMP v6 */
                header_icmp6_print_complete (stdout, bytes);
                bytes = NULL;
                break;
            default:
                break;
        }

    if (bytes != NULL)
    {
        #define __text_application(port,name) \
            if (source_port == (port) || dest_port == (port)) \
            { \
                __print_name (stdout, (name)); \
                __print_bytes (stdout, bytes, limit); \
                fprintf (stdout, "\n\n"); \
            }

        #define __encrypted_text_application(port,name) \
            if (source_port == (port) || dest_port == (port)) \
            { \
                __print_name (stdout, (name)); \
                __raw_packet_print (stdout, bytes, (size_t) (limit - bytes)); \
            }

        __text_application (20, "FTP data");
        __text_application (21, "FTP control");
        __text_application (25, "SMTP");
        __text_application (80, "HTTP");
        __text_application (110, "POP");
        __text_application (143, "IMAP");

        __encrypted_text_application (443, "HTTPS");
        __encrypted_text_application (465, "Encrypted SMTP");
        __encrypted_text_application (993, "Encrypted IMAP");
        __encrypted_text_application (995, "Encrypted POP");

        if (source_port == 67 || dest_port == 67 || source_port == 68
                || dest_port == 68)
            bootp_print (stdout, (const bootp_header *) bytes);

        #undef __text_application
        #undef __encrypted_text_application
    }
}

////////////////////////////////////////////////////////////////////////////////
// Misc.
////////////////////////////////////////////////////////////////////////////////

void __print_name (FILE * const stream, const char * const name)
{
    size_t name_size = strlen (name);
    char buffer[name_size + 1];

    /* Fill the buffer with '=' characters. */
    for (size_t i = 0; i < name_size; ++i)
        buffer[i] = '=';
    buffer[name_size] = '\0';

    fprintf (stream, "%s\n%s\n", name, buffer);
}

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

void __print_bytes (FILE * const stream, const u_char * bytes,
        const u_char * const limit)
{
    for ( ; bytes < limit; ++bytes)
    {
        u_char current_byte = bytes[0];
        if (current_byte == 0x0d && bytes[1] == 0x0a)
        {
            fprintf (stream, "\n");
            ++bytes;
        }
        else
            fprintf (stream, "%c",
                    (* bytes) > 31 && (* bytes) < 127 ? * bytes : '.');
    }
}

void __print_bytes_start (FILE * const stream, const u_char * bytes,
        const u_char * const limit)
{
    for ( ; bytes < limit; ++bytes)
    {
        u_char current_byte = bytes[0];
        if (current_byte == 0x0d && bytes[1] == 0x0a)
        {
            fprintf (stream, "\n");
            break;
        }
        else
            fprintf (stream, "%c",
                    (* bytes) > 31 && (* bytes) < 127 ? * bytes : '.');
    }
}
