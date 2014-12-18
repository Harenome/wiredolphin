/**
 * \file main.c
 * \brief Main.
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

#include <stdlib.h>
#include <stdio.h>

#include "wiredolphin/version.h"

int main (int argc, char ** argv)
{
    fprintf (stderr, "wiredolphin version %u.%u.%u, 2014\n",
        WIREDOLPHIN_VERSION_MAJOR, WIREDOLPHIN_VERSION_MINOR,
        WIREDOLPHIN_VERSION_PATCH);
    fprintf (stderr, "This program does not do anything yet.\n");
}
