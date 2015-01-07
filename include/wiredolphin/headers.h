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

#include <arpa/inet.h>
#include <net/ethernet.h>

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

#endif /* __HEADERS_H__ */
