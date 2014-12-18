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

#include <pcap/pcap.h>

/**
 * \brief Merely print a packet.
 */
void callback_raw_packet (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

void callback_info_concise (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

void callback_info_synthetic (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

void callback_info_complete (u_char * user, const struct pcap_pkthdr * header,
    const u_char * bytes);

#endif /* __CALLBACK_H__ */
