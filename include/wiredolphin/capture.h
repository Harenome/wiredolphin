/**
 * \file capture.h
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

#ifndef __CAPTURE_H__
#define __CAPTURE_H__

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <pcap/pcap.h>

#include "wiredolphin/callback.h"

/**
 * \brief Check whether an interface is available.
 * \param interface Interface name.
 * \retval true If the interface is available.
 * \retval false otherwise.
 */
bool check_interface (const char * interface);

/**
 * \brief Monitor an interface using a filter.
 * \param interface Interface name.
 * \param filter Filter.
 */
void monitor_interface (const char * interface, const char * filter);

#endif /* __CAPTURE_H__ */
