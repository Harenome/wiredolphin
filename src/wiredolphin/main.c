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
#include <sysexits.h>
#include <unistd.h>
#include <getopt.h>

#include "wiredolphin/capture.h"
#include "wiredolphin/version.h"

////////////////////////////////////////////////////////////////////////////////
// Static utilities.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Interface to monitor.
 */
static char * __interface = "lo";

/**
 * \brief Filter to use.
 */
static char * __filter = "any";

/**
 * \brief Offline capture file to monitor.
 */
static char * __offline = NULL;

/**
 * \brief Parse command line arguments.
 * \param argc Argument count.
 * \param argv Command line arguments.
 */
static inline void __parse_args (int argc, char ** argv);

/**
 * \brief Print the help.
 */
static inline void __print_help (void);

////////////////////////////////////////////////////////////////////////////////
// Main.
////////////////////////////////////////////////////////////////////////////////

/**
 * \brief Main function.
 * \param argc Argument count.
 * \param argv Command line arguments.
 */
int main (int argc, char ** argv)
{
    if (argc == 1)
    {
        fprintf (stderr, "Usage: %s <interface>\n", * argv);
        exit (EX_USAGE);
    }

    __parse_args (argc, argv);

    fprintf (stderr, "wiredolphin version %u.%u.%u, 2014-2015\n\n",
        WIREDOLPHIN_VERSION_MAJOR, WIREDOLPHIN_VERSION_MINOR,
        WIREDOLPHIN_VERSION_PATCH);

    if (__offline)
        monitor_file (__offline, __filter);
    else
        monitor_interface (__interface, __filter);

    exit (EXIT_SUCCESS);
}

////////////////////////////////////////////////////////////////////////////////
// Misc.
////////////////////////////////////////////////////////////////////////////////

void __parse_args (int argc, char ** argv)
{
    static const struct option wiredolphin_options[] =
    {
        { "interface",  required_argument, NULL, 'i', },
        { "offline",    required_argument, NULL, 'o', },
        { "filter",     required_argument, NULL, 'f', },
        { "verbose",    required_argument, NULL, 'v', },
        { "help",       no_argument, NULL, 'h', },
        { 0, 0, 0, 0, },
    };

    int val = 1;
    unsigned int verbose_mode = 3;

    do
    {
        int longindex;
        val = getopt_long (argc, argv, "i:o:f:v:h", wiredolphin_options,
                & longindex);

        switch (val)
        {
            case 'i':
                __interface = optarg;
                break;
            case 'o':
                __offline = optarg;
                break;
            case 'f':
                __filter = optarg;
                break;
            case 'v':
                if (sscanf (optarg, "%u", & verbose_mode) != 1)
                {
                    perror ("sscanf");
                    exit (EX_USAGE);
                }
                set_callback (verbose_mode);
                break;
            case 'h':
                __print_help ();
                exit (EXIT_SUCCESS);
                break;
            case ':':
                fprintf (stderr, "Error: missing argument for \"%s\".\n",
                        argv[optind-1]);
                exit (EX_USAGE);
            case '?':
                fprintf (stderr, "Error: Unknown option \"%s\".\n",
                        argv[optind-1]);
                exit (EX_USAGE);
            default:
                break;
        }
    }
    while (val != - 1);
}

void __print_help (void)
{
    fprintf (stderr, "wiredolphin [OPTIONS]\n\n");
    fprintf (stderr, "OPTIONS:\n\n");

    fprintf (stderr, "\t-f, --filter <filter>\n");
    fprintf (stderr, "\t\tMonitor using the filter <filter>.\n");

    fprintf (stderr, "\t-h, --help\n");
    fprintf (stderr, "\t\tPrint this help.\n");

    fprintf (stderr, "\t-i, --interface <interface_name>\n");
    fprintf (stderr, "\t\tMonitor the interface <interface_name>.\n");

    fprintf (stderr, "\t-o, --offline <file>\n");
    fprintf (stderr, "\t\tMonitor the offline capture file <file>.\n");

    fprintf (stderr, "\t-v, --verbose <level>\n");
    fprintf (stderr, "\t\tSet the verbose mode level.\n");
    fprintf (stderr, "\t\t0: Raw.\n");
    fprintf (stderr, "\t\t1: Concise.\n");
    fprintf (stderr, "\t\t2: Synthetic.\n");
    fprintf (stderr, "\t\t3: Complete.\n");

    fprintf (stderr, "\n");

    fprintf (stderr, "wiredolphin version %u.%u.%u, 2014-2015\n\n",
            WIREDOLPHIN_VERSION_MAJOR, WIREDOLPHIN_VERSION_MINOR,
            WIREDOLPHIN_VERSION_PATCH);
}
