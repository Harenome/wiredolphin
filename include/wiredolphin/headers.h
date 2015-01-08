/**
 * \file headers.h
 * \brief Headers.
 * \author RAZANAJATO RANAIVOARIVONY Harenome
 * \date 2014
 * \copyright WTFPLv2
 *
 * Utilities to extract and print information from various frames and headers.
 */
/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://www.wtfpl.net/ for more details.
 */

#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <pcap/pcap.h>

////////////////////////////////////////////////////////////////////////////////
// Ethernet frames.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print complete information on an ethernet frame.
 * \param stream Output stream.
 * \param bytes The ethernet frame.
 */
void header_ethernet_print_complete (FILE * stream, const u_char * bytes);

/**
 * \brief Print synthetic information on an ethernet frame.
 * \param stream Output stream.
 * \param bytes The ethernet frame.
 */
void header_ethernet_print_synthetic (FILE * stream, const u_char * bytes);

/**
 * \brief Get the packet type from an ethernet frame.
 * \param bytes The ethernet frame.
 * \return The packet type (see the \c ETHERTYPE_x macros in \c net/ethernet.h).
 */
uint16_t header_ethernet_packet_type (const u_char * bytes);

/**
 * \brief Get a pointer to the data from an ethernet frame.
 * \param bytes The ethernet frame.
 * \return The data.
 */
const u_char * header_ethernet_data (const u_char * bytes);

////////////////////////////////////////////////////////////////////////////////
// IP headers.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print complete information on an IPv4 header.
 * \param stream Output stream.
 * \param bytes The IPv4 header.
 */
void header_ipv4_print_complete (FILE * stream, const u_char * bytes);

/**
 * \brief Print synthetic information on an IPv4 header.
 * \param stream Output stream.
 * \param bytes The IPv4 header.
 */
void header_ipv4_print_synthetic (FILE * stream, const u_char * bytes);

/**
 * \brief Print concise information on an IPv4 header.
 * \param stream Output stream.
 * \param bytes The IPv4 header.
 */
void header_ipv4_print_concise (FILE * stream, const u_char * bytes);

/**
 * \brief Get an IPv4 header's data.
 * \param bytes The IPv4 header.
 * \return The data.
 */
const u_char * header_ipv4_data (const u_char * bytes);

/**
 * \brief Get an IPv4 header's protocol.
 * \param bytes The IPv4 header.
 * \return The protocol.
 */
u_int8_t header_ipv4_protocol (const u_char * bytes);

////////////////////////////////////////////////////////////////////////////////
// ARP headers.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print complete information on an ARP header.
 * \param stream Output stream.
 * \param bytes The ARP header.
 */
void header_arp_print_complete (FILE * stream, const u_char * bytes);

/**
 * \brief Print synthetic information on an ARP header.
 * \param stream Output stream.
 * \param bytes The ARP header.
 */
void header_arp_print_synthetic (FILE * stream, const u_char * bytes);

/**
 * \brief Print concise information on an ARP header.
 * \param stream Output stream.
 * \param bytes The ARP header.
 */
void header_arp_print_concise (FILE * stream, const u_char * bytes);

////////////////////////////////////////////////////////////////////////////////
// ICMP headers.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print complete information on an ICMP header.
 * \param stream Output stream.
 * \param bytes The ICMP header.
 */
void header_icmp4_print_complete (FILE * stream, const u_char * bytes);

/**
 * \brief Print synthetic information on an ICMP header.
 * \param stream Output stream.
 * \param bytes The ICMP header.
 */
void header_icmp4_print_synthetic (FILE * stream, const u_char * bytes);

/**
 * \brief Print concise information on an ICMP header.
 * \param stream Output stream.
 * \param bytes The ICMP header.
 */
void header_icmp4_print_concise (FILE * stream, const u_char * bytes);

////////////////////////////////////////////////////////////////////////////////
// TCP headers.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print complete information on a TCP header.
 * \param stream Output stream.
 * \param bytes The TCP header.
 */
void header_tcp4_print_complete (FILE * stream, const u_char * bytes);

/**
 * \brief Print synthetic information on a TCP header.
 * \param stream Output stream.
 * \param bytes The TCP header.
 */
void header_tcp4_print_synthetic (FILE * stream, const u_char * bytes);

/**
 * \brief Print concise information on a TCP header.
 * \param stream Output stream.
 * \param bytes The TCP header.
 */
void header_tcp4_print_concise (FILE * stream, const u_char * bytes);

/**
 * \brief Get a TCP packet's data.
 * \param bytes The TCP header.
 * \return The data.
 */
const u_char * header_tcp4_data (const u_char * bytes);

////////////////////////////////////////////////////////////////////////////////
// UDP headers.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Print complete information on an UDP header.
 * \param stream Output stream.
 * \param bytes The UDP header.
 */
void header_udp4_print_complete (FILE * stream, const u_char * bytes);

/**
 * \brief Print synthetic information on an UDP header.
 * \param stream Output stream.
 * \param bytes The UDP header.
 */
void header_udp4_print_synthetic (FILE * stream, const u_char * bytes);

/**
 * \brief Print concise information on an UDP header.
 * \param stream Output stream.
 * \param bytes The UDP header.
 */
void header_udp4_print_concise (FILE * stream, const u_char * bytes);

/**
 * \brief Get an UDP packet's data.
 * \param bytes The UDP header.
 * \return The data.
 */
const u_char * header_udp4_data (const u_char * bytes);

#endif /* __HEADERS_H__ */
