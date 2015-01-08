/**
 * \file capture.c
 * \brief Capture.
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

#include "wiredolphin/capture.h"

static pcap_handler wiredolphin_callback = callback_info_complete;

bool check_interface (const char * interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t * device_list;

    int success = pcap_findalldevs (& device_list, error_buffer);

    if (! success)
    {
        success = -1;
        for (pcap_if_t * current = device_list; success && current != NULL;
            current = current->next)
            success = strcmp (interface, current->name);
    }

    pcap_freealldevs (device_list);

    return success == 0;
}

void monitor_interface (const char * interface, const char * filter)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program compiled_filter;

    if (check_interface (interface))
    {
        pcap_t * capture = pcap_open_live (interface, 65535, 0, 0, error_buffer);
        if (capture != NULL)
        {
            pcap_compile (capture, & compiled_filter, filter, 0, 0);
            pcap_setfilter (capture, & compiled_filter);
            pcap_loop (capture, -1, wiredolphin_callback, NULL);
        }
        else
            fprintf (stderr, "Error: Could not open capture.\n");
    }
    else
        fprintf (stderr, "Error: interface %s not found.\n", interface);
}

void monitor_file (const char * file, const char * filter)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    struct bpf_program compiled_filter;

    pcap_t * capture = pcap_open_offline (file, error_buffer);
    if (capture != NULL)
    {
        pcap_compile (capture, & compiled_filter, filter, 0, 0);
        pcap_setfilter (capture, & compiled_filter);
        pcap_loop (capture, -1, wiredolphin_callback, NULL);
    }
    else
        fprintf (stderr, "Error: Could not open capture.\n");
}

void set_callback (unsigned int id)
{
    static pcap_handler callbacks[] =
    {
        [0] = callback_raw_packet,
        [1] = callback_info_concise,
        [2] = callback_info_synthetic,
        [3] = callback_info_complete,
    };

    wiredolphin_callback = callbacks[id < 4 ? id : 3];
}
