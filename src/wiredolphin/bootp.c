/**
 * \file bootp.c
 * \brief BOOTP.
 * \author RAZANAJATO RANAIVOARIVONY Harenome
 * \date 2015
 * \copyright WTFPLv2
 */
/* This program is free software. It comes without any warranty, to
 * the extent permitted by applicable law. You can redistribute it
 * and/or modify it under the terms of the Do What The Fuck You Want
 * To Public License, Version 2, as published by Sam Hocevar. See
 * http://www.wtfpl.net/ for more details.
 */

#include "wiredolphin/bootp.h"

////////////////////////////////////////////////////////////////////////////////
// BOOTP.
////////////////////////////////////////////////////////////////////////////////

const char * bootp_opcode_string (u_int8_t opcode)
{
    static const char * opcode_strings[] =
    {
        [0] = "BOOTP request",
        [1] = "BOOTP reply",
        [2] = "Unknown",
    };

    return opcode_strings[opcode <= 1 ? opcode : 2];
}

void bootp_print (FILE * const stream, const bootp_header * const header)
{
    fprintf (stream, "BOOTP header\n============\n");

    fprintf (stream, "%-24s\t%s\n", "Operation:",
            bootp_opcode_string (header->opcode));
    fprintf (stream, "%-24s\t%u\n", "Hardware type:", header->hw_type);
    fprintf (stream, "%-24s\t%u\n", "Hardware address length:",
            header->hw_addr_len);
    fprintf (stream, "%-24s\t%u\n", "Hop count:", header->hop_count);
    fprintf (stream, "%-24s\t%u\n", "Transaction ID:", header->transaction_id);
    fprintf (stream, "%-24s\t%u\n", "Seconds count:", header->seconds_count);
    fprintf (stream, "%-24s\t%s\n", "Client address:",
            inet_ntoa (header->client_addr));
    fprintf (stream, "%-24s\t%s\n", "Your address:",
            inet_ntoa (header->your_addr));
    fprintf (stream, "%-24s\t%s\n", "Server address:",
            inet_ntoa (header->server_addr));
    fprintf (stream, "%-24s\t%s\n", "Gateway address:",
            inet_ntoa (header->gateway_addr));
    fprintf (stream, "%-24s\t%s\n", "Hardware address:",
            ether_ntoa ((const struct ether_addr *) header->hw_addr));
    fprintf (stream, "%-24s\t%64s\n", "Server hostname:", header->server_hostname);
    fprintf (stream, "%-24s\t%128s\n", "Boot filename:", header->boot_filename);

    const u_int32_t * cookie = (const u_int32_t *) header->vendor_specific;
    if (ntohl (* cookie) == BOOTP_MAGIC_COOKIE)
    {
        fprintf (stream, "\nDHCP header\n===========\n");
        fprintf (stream, "%-24s\t0x%x\n", "DHCP cookie found:",
                ntohl (* cookie));

        const u_int8_t * limit = (const u_int8_t *) header;
        limit += sizeof (bootp_header);

        const u_int8_t * bytes = (const u_int8_t *) & cookie[1];
        while (bytes < limit)
        {
            bootp_tlv tlv = bootp_extract_tlv (bytes);
            bootp_option_print (stream, & tlv);
            fprintf (stream, "\n");
            bytes = tlv.next;
        }
    }

    fprintf (stream, "\n");
}

////////////////////////////////////////////////////////////////////////////////
// BOOTP Vendor Specific.
////////////////////////////////////////////////////////////////////////////////

bootp_tlv bootp_extract_tlv (const u_int8_t * bytes)
{
    bootp_tlv tlv;
    tlv.type = bytes[0];
    tlv.length = bytes[1];
    tlv.value = & bytes[2];
    tlv.next = tlv.value + tlv.length;

    return tlv;
}

void bootp_option_print (FILE * stream, const bootp_tlv * option)
{
    char char_buffer[option->length + 1];
    const struct in_addr * addr;

    switch (option->type)
    {
        case BOOTP_DHCP_SUBNET_MASK:
            addr = (const struct in_addr *) option->value;
            fprintf (stream, "%-24s\t%s", "Subnet mask:", inet_ntoa (* addr));
            break;
        case BOOTP_DHCP_ROUTER:
        case BOOTP_DHCP_DNS:
            fprintf (stream, "%-24s\n",
                    option->type == BOOTP_DHCP_ROUTER ? "Routers:" : "Dns:");
            addr = (const struct in_addr *) option->value;
            for (u_int8_t i = 0; i < option->length / 4; ++i)
                fprintf (stream, "\t%s%c",
                        inet_ntoa (addr[i]),
                        (i + 1) < (option->length / 4) ? '\n' : '\0');
            break;
        case BOOTP_DHCP_HOSTNAME:
        case BOOTP_DHCP_DOMAINNAME:
            strncpy (char_buffer, (const char *) option->value, option->length);
            char_buffer[option->length] = '\0';
            fprintf (stream, "%-24s\t%s",
                option->type == BOOTP_DHCP_HOSTNAME ? "Hostname:" : "Domain name:",
                char_buffer);
            break;
        case BOOTP_DHCP_BROADCAST_ADDR:
            addr = (const struct in_addr *) option->value;
            fprintf (stream, "%-24s\t%s", "Broadcast address:", inet_ntoa (* addr));
            break;
        case BOOTP_DHCP_MESSAGE:
            fprintf (stream, "%-24s\t%s", "DHCP message type:",
                    dhcp_message_type_string (option->value[0]));
            break;
        case BOOTP_DHCP_PAR_REQ_LIST:
            fprintf (stream, "Parameter request list:\n\t");
            for (u_int8_t i = 0; i < option->length; ++i)
                fprintf (stream, "%u ", option->value[i]);
            break;
        case 255:
            fprintf (stream, "DHCP options end");
            break;
        default:
            fprintf (stream, "DHCP option %.3u", option->type);
            break;
    }
}

////////////////////////////////////////////////////////////////////////////////
// DHCP utilities.
////////////////////////////////////////////////////////////////////////////////

const char * dhcp_message_type_string (dhcp_message_type type)
{
    static const char * dhcp_message_strings[] =
    {
        [0]             = "Unknown",
        [DHCP_DISCOVER] = "DHCP_DISCOVER",
        [DHCP_OFFER]    = "DHCP_OFFER",
        [DHCP_REQUEST]  = "DHCP_REQUEST",
        [DHCP_DECLINE]  = "DHCP_DECLINE",
        [DHCP_ACK]      = "DHCP_ACK",
        [DHCP_NACK]     = "DHCP_NACK",
        [DHCP_RELEASE]  = "DHCP_RELEASE",
    };

    return dhcp_message_strings[type > 0 && type <= DHCP_RELEASE ? type : 0];
}
