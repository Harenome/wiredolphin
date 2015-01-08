/**
 * \file callback.h
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

#ifndef __CALLBACK_H__
#define __CALLBACK_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <pcap/pcap.h>

#include "wiredolphin/headers.h"
#include "wiredolphin/bootp.h"

/**
 * \brief Merely print a packet.
 * \param user Additional user parameters.
 * \param header pcap header.
 * \param bytes Data.
 */
void callback_raw_packet (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

/**
 * \brief Print concise information on a packet.
 * \param user Additional user parameters.
 * \param header pcap header.
 * \param bytes Data.
 */
void callback_info_concise (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

/**
 * \brief Print synthetic information on a packet.
 * \param user Additional user parameters.
 * \param header pcap header.
 * \param bytes Data.
 */
void callback_info_synthetic (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

/**
 * \brief Print complete information on a packet.
 * \param user Additional user parameters.
 * \param header pcap header.
 * \param bytes Data.
 */
void callback_info_complete (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

#endif /* __CALLBACK_H__ */
