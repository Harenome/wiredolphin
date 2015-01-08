/**
 * \file bootp.h
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

#ifndef __BOOTP_H__
#define __BOOTP_H__

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

////////////////////////////////////////////////////////////////////////////////
// BOOTP.
////////////////////////////////////////////////////////////////////////////////

#define BOOTP_HW_ADDR_LEN   16  /**< Default hardware address length. */
#define BOOTP_HOSTNAME_LEN  64  /**< Default server hostname length. */
#define BOOTP_FILENAME_LEN  128 /**< Default boot filename length. */
#define BOOTP_VSPECIFIC_LEN 64  /**< Default vendor specific length. */

/**
 * BOOTP Header.
 */
typedef struct bootp_header
{
    u_int8_t opcode;                                /**< Opcode. */
    u_int8_t hw_type;                               /**< Hardware type. */
    u_int8_t hw_addr_len;                           /**< Hardware address length. */
    u_int8_t hop_count;                             /**< Hop count. */
    u_int32_t transaction_id;                       /**< Transaction ID. */
    u_int16_t seconds_count;                        /**< Seconds count. */
    u_int16_t unused;                               /**< Unused?! */
    struct in_addr client_addr;                     /**< Client address. */
    struct in_addr your_addr;                       /**< Your address. */
    struct in_addr server_addr;                     /**< Server address. */
    struct in_addr gateway_addr;                    /**< Gateway address. */
    u_int8_t hw_addr[BOOTP_HW_ADDR_LEN];            /**< Hardware address. */
    u_int8_t server_hostname[BOOTP_HOSTNAME_LEN];   /**< Server hostname. */
    u_int8_t boot_filename[BOOTP_FILENAME_LEN];     /**< Boot filename. */
    u_int8_t vendor_specific[BOOTP_VSPECIFIC_LEN];  /**< Vendor specific. */
} bootp_header;

/**
 * \brief Convert a BOOTP opcode into a string.
 * \param opcode BOOTP opcode.
 * \return String.
 */
const char * bootp_opcode_string (u_int8_t opcode);

/**
 * \brief Print a BOOTP header.
 * \param stream Output stream.
 * \param header BOOTP header.
 */
void bootp_print (FILE * stream, const bootp_header * header);

////////////////////////////////////////////////////////////////////////////////
// BOOTP Vendor Specific.
////////////////////////////////////////////////////////////////////////////////

#define BOOTP_MAGIC_COOKIE 0x63825363

/**
 * BOOTP Vendor Specific Type-Length-Value options.
 */
typedef struct bootp_tlv
{
    u_int8_t type;          /**< Type. */
    u_int8_t length;        /**< Length. */
    const u_int8_t * value; /**< Value. */
    const u_int8_t * next;  /**< Next TLV. */
} bootp_tlv;

/**
 * \brief Extract a BOOTP TLV.
 * \param bytes Bytes.
 * \return TLV.
 */
bootp_tlv bootp_extract_tlv (const u_int8_t * bytes);

typedef enum bootp_option
{
    BOOTP_DHCP_SUBNET_MASK = 1,
    BOOTP_DHCP_ROUTER = 3,
    BOOTP_DHCP_DNS = 6,
    BOOTP_DHCP_HOSTNAME = 12,
    BOOTP_DHCP_DOMAINNAME = 15,
    BOOTP_DHCP_BROADCAST_ADDR = 28,
    BOOTP_DHCP_MESSAGE = 53,
    BOOTP_DHCP_PAR_REQ_LIST = 55,
} bootp_option;

/**
 * \brief Print a BOOTP option.
 * \param stream Output stream.
 * \param option BOOTP option.
 */
void bootp_option_print (FILE * stream, const bootp_tlv * option);

////////////////////////////////////////////////////////////////////////////////
// DHCP utilities.
////////////////////////////////////////////////////////////////////////////////

typedef enum dhcp_message_type
{
    DHCP_DISCOVER   = 1,
    DHCP_OFFER      = 2,
    DHCP_REQUEST    = 3,
    DHCP_DECLINE    = 4,
    DHCP_ACK        = 5,
    DHCP_NACK       = 6,
    DHCP_RELEASE    = 7,
} dhcp_message_type;

/**
 * \brief Convert a DHCP message type to a string.
 * \param type Message type.
 */
const char * dhcp_message_type_string (dhcp_message_type type);

#endif /* __BOOTP_H__ */
