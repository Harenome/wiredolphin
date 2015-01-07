/**
 * \file headers.h
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

#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <stdlib.h>
#include <stdio.h>

#include <arpa/inet.h>
#include <net/ethernet.h>

#include <pcap/pcap.h>

void header_ethernet_print_complete (const u_char * bytes);

void header_ethernet_print_synthetic (const u_char * bytes);

uint16_t header_ethernet_packet_type (const u_char * bytes);

const u_char * header_ethernet_data (const u_char * bytes);

#endif /* __HEADERS_H__ */
