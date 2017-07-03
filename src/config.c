/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_interrupts.h>
#include <rte_ip.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_lpm.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_pci.h>
#include <rte_per_lcore.h>
#include <rte_per_lcore.h>
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_ring.h>
#include <rte_string_fns.h>
#include <rte_tailq.h>
#include <rte_tcp.h>

#include "main.h"

struct app_params app;

static const char usage[] =
    "                                                                               \n"
    "    hpcn_pcapreplay <EAL PARAMS> -- <APP PARAMS>                               \n"
    "                                                                               \n"
    "Application manadatory parameters:                                             \n"
    "    --rx \"(PORT, QUEUE, LCORE), ...\" : List of NIC RX ports and queues       \n"
    "           handled by the I/O RX lcores                                        \n"
    "    --tx \"(PORT, QUEUE, LCORE), ...\" : List of NIC TX ports and queues       \n"
    "           handled by the I/O TX lcores                                        \n"
    "    --pcap \"file.pcap\" : the pcap file to send   \n"

    "                                                                               \n"
    "Application optional parameters:                                               \n"
    "    --rsz \"A, B\" : Ring sizes                                                \n"
    "           A = Size (in number of buffer descriptors) of each of the NIC RX    \n"
    "               rings read by the I/O RX lcores (default value is %u)           \n"
    "           B = Size (in number of buffer descriptors) of each of the NIC TX    \n"
    "               rings written by I/O TX lcores (default value is %u)            \n"
    "    --bsz \"A, B\" :  Burst sizes                                              \n"
    "           A = I/O RX lcore read burst size from NIC RX (default value is %u)  \n"
    "           B = I/O TX lcore write burst size to NIC TX (default value is %u)   \n"
    "    --caida: Use CAIDA trace\n";

void app_print_usage (void) {
	printf (usage,
	        APP_DEFAULT_NIC_RX_RING_SIZE,
	        APP_DEFAULT_NIC_TX_RING_SIZE,
	        APP_DEFAULT_BURST_SIZE_IO_RX_READ,
	        APP_DEFAULT_BURST_SIZE_IO_TX_WRITE);
}

#ifndef APP_ARG_RX_MAX_CHARS
#define APP_ARG_RX_MAX_CHARS 4096
#endif

#ifndef APP_ARG_RX_MAX_TUPLES
#define APP_ARG_RX_MAX_TUPLES 128
#endif

static int str_to_unsigned_array (
    const char *s, size_t sbuflen, char separator, unsigned num_vals, unsigned *vals) {
	char str[sbuflen + 1];
	char *splits[num_vals];
	char *endptr = NULL;
	int i, num_splits = 0;

	/* copy s so we don't modify original string */
	snprintf (str, sizeof (str), "%s", s);
	num_splits = rte_strsplit (str, sizeof (str), splits, num_vals, separator);

	errno = 0;
	for (i = 0; i < num_splits; i++) {
		vals[i] = strtoul (splits[i], &endptr, 0);
		if (errno != 0 || *endptr != '\0')
			return -1;
	}

	return num_splits;
}

static int str_to_unsigned_vals (
    const char *s, size_t sbuflen, char separator, unsigned num_vals, ...) {
	unsigned i, vals[num_vals];
	va_list ap;

	num_vals = str_to_unsigned_array (s, sbuflen, separator, num_vals, vals);

	va_start (ap, num_vals);
	for (i = 0; i < num_vals; i++) {
		unsigned *u = va_arg (ap, unsigned *);
		*u          = vals[i];
	}
	va_end (ap);
	return num_vals;
}

static int parse_arg_rx (const char *arg) {
	const char *p0 = arg, *p = arg;
	uint32_t n_tuples;

	if (strnlen (arg, APP_ARG_RX_MAX_CHARS + 1) == APP_ARG_RX_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while ((p = strchr (p0, '(')) != NULL) {
		struct app_lcore_params *lp;
		uint32_t port, queue, lcore, i;

		p0 = strchr (p++, ')');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals (p, p0 - p, ',', 3, &port, &queue, &lcore) != 3)) {
			return -2;
		}

		/* Enable port and queue for later initialization */
		if ((port >= APP_MAX_NIC_PORTS) || (queue >= APP_MAX_RX_QUEUES_PER_NIC_PORT)) {
			return -3;
		}
		if (app.nic_rx_queue_mask[port][queue] != 0) {
			return -4;
		}
		app.nic_rx_queue_mask[port][queue] = 1;

		/* Check and assign (port, queue) to I/O lcore */
		if (rte_lcore_is_enabled (lcore) == 0) {
			return -5;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -6;
		}
		lp = &app.lcore_params[lcore];
		//if (lp->type == e_APP_LCORE_WORKER) {
		//	return -7;
		//}
		lp->type = e_APP_LCORE_IO;
		for (i = 0; i < lp->io.rx.n_nic_queues; i++) {
			if ((lp->io.rx.nic_queues[i].port == port) &&
			    (lp->io.rx.nic_queues[i].queue == queue)) {
				return -8;
			}
		}
		if (lp->io.rx.n_nic_queues >= APP_MAX_NIC_RX_QUEUES_PER_IO_LCORE) {
			return -9;
		}
		lp->io.rx.nic_queues[lp->io.rx.n_nic_queues].port  = (uint8_t)port;
		lp->io.rx.nic_queues[lp->io.rx.n_nic_queues].queue = (uint8_t)queue;
		lp->io.rx.n_nic_queues++;

		n_tuples++;
		if (n_tuples > APP_ARG_RX_MAX_TUPLES) {
			return -10;
		}
	}

	if (n_tuples == 0) {
		return -11;
	}

	return 0;
}

#ifndef APP_ARG_TX_MAX_CHARS
#define APP_ARG_TX_MAX_CHARS 4096
#endif

#ifndef APP_ARG_TX_MAX_TUPLES
#define APP_ARG_TX_MAX_TUPLES 128
#endif

static int parse_arg_tx (const char *arg) {
	const char *p0 = arg, *p = arg;
	uint32_t n_tuples;

	if (strnlen (arg, APP_ARG_TX_MAX_CHARS + 1) == APP_ARG_TX_MAX_CHARS + 1) {
		return -1;
	}

	n_tuples = 0;
	while ((p = strchr (p0, '(')) != NULL) {
		struct app_lcore_params *lp;
		uint32_t port, queue, lcore, i;

		p0 = strchr (p++, ')');
		if ((p0 == NULL) ||
		    (str_to_unsigned_vals (p, p0 - p, ',', 3, &port, &queue, &lcore) != 3)) {
			return -2;
		}

		/* Enable port and queue for later initialization */
		if ((port >= APP_MAX_NIC_PORTS) || (queue >= APP_MAX_TX_QUEUES_PER_NIC_PORT)) {
			return -3;
		}
		if (app.nic_tx_queue_mask[port][queue] != 0) {
			return -4;
		}
		app.nic_tx_queue_mask[port][queue] = 1;

		/* Check and assign (port, queue) to I/O lcore */
		if (rte_lcore_is_enabled (lcore) == 0) {
			return -5;
		}

		if (lcore >= APP_MAX_LCORES) {
			return -6;
		}
		lp = &app.lcore_params[lcore];
		//if (lp->type == e_APP_LCORE_WORKER) {
		//	return -7;
		//}
		lp->type = e_APP_LCORE_IO;
		for (i = 0; i < lp->io.tx.n_nic_queues; i++) {
			if ((lp->io.tx.nic_queues[i].port == port) &&
			    (lp->io.tx.nic_queues[i].queue == queue)) {
				return -8;
			}
		}
		if (lp->io.tx.n_nic_queues >= APP_MAX_NIC_TX_QUEUES_PER_IO_LCORE) {
			return -9;
		}
		lp->io.tx.nic_queues[lp->io.tx.n_nic_queues].port  = (uint8_t)port;
		lp->io.tx.nic_queues[lp->io.tx.n_nic_queues].queue = (uint8_t)queue;
		lp->io.tx.n_nic_queues++;

		n_tuples++;
		if (n_tuples > APP_ARG_TX_MAX_TUPLES) {
			return -10;
		}
	}

	if (n_tuples == 0) {
		return -11;
	}

	return 0;
}

#ifndef APP_ARG_RSZ_CHARS
#define APP_ARG_RSZ_CHARS 63
#endif

static int parse_arg_rsz (const char *arg) {
	if (strnlen (arg, APP_ARG_RSZ_CHARS + 1) == APP_ARG_RSZ_CHARS + 1) {
		return -1;
	}

	if (str_to_unsigned_vals (
	        arg, APP_ARG_RSZ_CHARS, ',', 2, &app.nic_rx_ring_size, &app.nic_tx_ring_size) != 2)
		return -2;

	if ((app.nic_rx_ring_size == 0) || (app.nic_tx_ring_size == 0)) {
		return -3;
	}

	return 0;
}

#ifndef APP_ARG_BSZ_CHARS
#define APP_ARG_BSZ_CHARS 63
#endif

static int parse_arg_bsz (const char *arg) {
	if (strnlen (arg, APP_ARG_BSZ_CHARS + 1) == APP_ARG_BSZ_CHARS + 1) {
		return -1;
	}

	if (str_to_unsigned_vals (arg,
	                          APP_ARG_BSZ_CHARS,
	                          ',',
	                          2,
	                          &app.burst_size_io_rx_read,
	                          &app.burst_size_io_tx_write) != 2)
		return -2;

	if ((app.burst_size_io_rx_read == 0) || (app.burst_size_io_tx_write == 0)) {
		return -7;
	}

	if ((app.burst_size_io_rx_read > APP_MBUF_ARRAY_SIZE) ||
	    (app.burst_size_io_tx_write > APP_MBUF_ARRAY_SIZE)) {
		return -8;
	}

	return 0;
}

#ifndef APP_ARG_NUMERICAL_SIZE_CHARS
#define APP_ARG_NUMERICAL_SIZE_CHARS 15
#endif

extern char pcap_File[256];
extern uint8_t caidaTrace;

/* Parse the argument given in the command line of the application */
int app_parse_args (int argc, char **argv) {
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname                 = argv[0];
	static struct option lgopts[] = {// aniadido
	                                 {"pcap", 1, 0, 0},
	                                 // normal
	                                 {"rx", 1, 0, 0},
	                                 {"tx", 1, 0, 0},
	                                 {"rsz", 1, 0, 0},
	                                 {"bsz", 1, 0, 0},
	                                 {"caida", 0, 0, 0},
	                                 {NULL, 0, 0, 0}};
	uint32_t arg_rx     = 0;
	uint32_t arg_tx     = 0;
	uint32_t arg_rsz    = 0;
	uint32_t arg_bsz    = 0;

	argvopt = argv;

	while ((opt = getopt_long (argc, argvopt, "", lgopts, &option_index)) != EOF) {
		switch (opt) {
			/* long options */
			case 0:
				if (!strcmp (lgopts[option_index].name, "rx")) {
					arg_rx = 1;
					ret    = parse_arg_rx (optarg);
					if (ret) {
						printf ("Incorrect value for --rx argument (%d)\n", ret);
						return -1;
					}
				}
				if (!strcmp (lgopts[option_index].name, "tx")) {
					arg_tx = 1;
					ret    = parse_arg_tx (optarg);
					if (ret) {
						printf ("Incorrect value for --tx argument (%d)\n", ret);
						return -1;
					}
				}
				if (!strcmp (lgopts[option_index].name, "pcap")) {
					strcpy (pcap_File, optarg);
					printf ("Pcap file set to %s\n", pcap_File);
				}
				if (!strcmp (lgopts[option_index].name, "rsz")) {
					arg_rsz = 1;
					ret     = parse_arg_rsz (optarg);
					if (ret) {
						printf ("Incorrect value for --rsz argument (%d)\n", ret);
						return -1;
					}
				}
				if (!strcmp (lgopts[option_index].name, "bsz")) {
					arg_bsz = 1;
					ret     = parse_arg_bsz (optarg);
					if (ret) {
						printf ("Incorrect value for --bsz argument (%d)\n", ret);
						return -1;
					}
				}
				if (!strcmp (lgopts[option_index].name, "caida")) {
					caidaTrace = 1;
				}
				break;

			default:
				return -1;
		}
	}

	/* Check that all mandatory arguments are provided */
	if ((arg_rx == 0) || (arg_tx == 0)) {
		printf ("Not all mandatory arguments are present\n");
		return -1;
	}

	/* Assign default values for the optional arguments not provided */
	if (arg_rsz == 0) {
		app.nic_rx_ring_size = APP_DEFAULT_NIC_RX_RING_SIZE;
		app.nic_tx_ring_size = APP_DEFAULT_NIC_TX_RING_SIZE;
	}

	if (arg_bsz == 0) {
		app.burst_size_io_rx_read  = APP_DEFAULT_BURST_SIZE_IO_RX_READ;
		app.burst_size_io_tx_write = APP_DEFAULT_BURST_SIZE_IO_TX_WRITE;
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	ret    = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

int app_get_nic_rx_queues_per_port (uint8_t port) {
	uint32_t i, count;

	if (port >= APP_MAX_NIC_PORTS) {
		return -1;
	}

	count = 0;
	for (i = 0; i < APP_MAX_RX_QUEUES_PER_NIC_PORT; i++) {
		if (app.nic_rx_queue_mask[port][i] == 1) {
			count++;
		}
	}

	return count;
}

int app_get_nic_tx_queues_per_port (uint8_t port) {
	uint32_t i, count;

	if (port >= APP_MAX_NIC_PORTS) {
		return -1;
	}

	count = 0;
	for (i = 0; i < APP_MAX_TX_QUEUES_PER_NIC_PORT; i++) {
		if (app.nic_tx_queue_mask[port][i] == 1) {
			count++;
		}
	}

	return count;
}

int app_get_lcore_for_nic_rx (uint8_t port, uint8_t queue, uint32_t *lcore_out) {
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
		uint32_t i;

		if (app.lcore_params[lcore].type != e_APP_LCORE_IO) {
			continue;
		}

		for (i = 0; i < lp->rx.n_nic_queues; i++) {
			if ((lp->rx.nic_queues[i].port == port) && (lp->rx.nic_queues[i].queue == queue)) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int app_get_lcore_for_nic_tx (uint8_t port, uint8_t queue, uint32_t *lcore_out) {
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
		uint32_t i;

		if (app.lcore_params[lcore].type != e_APP_LCORE_IO) {
			continue;
		}

		for (i = 0; i < lp->tx.n_nic_queues; i++) {
			if ((lp->tx.nic_queues[i].port == port) && (lp->tx.nic_queues[i].queue == queue)) {
				*lcore_out = lcore;
				return 0;
			}
		}
	}

	return -1;
}

int app_is_socket_used (uint32_t socket) {
	uint32_t lcore;

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		if (socket == rte_lcore_to_socket_id (lcore)) {
			return 1;
		}
	}

	return 0;
}

uint32_t app_get_lcores_io_rx (void) {
	uint32_t lcore, count;

	count = 0;
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) || (lp_io->rx.n_nic_queues == 0)) {
			continue;
		}

		count++;
	}

	return count;
}

void app_print_params (void) {
	unsigned port, queue, lcore, i /*, j*/;

	/* Print NIC RX configuration */
	printf ("NIC RX ports: ");
	for (port = 0; port < APP_MAX_NIC_PORTS; port++) {
		uint32_t n_rx_queues = app_get_nic_rx_queues_per_port ((uint8_t)port);

		if (n_rx_queues == 0) {
			continue;
		}

		printf ("%u (", port);
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue++) {
			if (app.nic_rx_queue_mask[port][queue] == 1) {
				printf ("%u ", queue);
			}
		}
		printf (")  ");
	}
	printf (";\n");

	/* Print I/O lcore RX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) || (lp->rx.n_nic_queues == 0)) {
			continue;
		}

		printf ("I/O lcore %u (socket %u): ", lcore, rte_lcore_to_socket_id (lcore));

		printf ("RX ports  ");
		for (i = 0; i < lp->rx.n_nic_queues; i++) {
			printf ("(%u, %u)  ",
			        (unsigned)lp->rx.nic_queues[i].port,
			        (unsigned)lp->rx.nic_queues[i].queue);
		}
		printf (";\n");
	}

	/* Print NIC TX configuration */
	printf ("NIC TX ports: ");
	for (port = 0; port < APP_MAX_NIC_PORTS; port++) {
		uint32_t n_tx_queues = app_get_nic_tx_queues_per_port ((uint8_t)port);

		if (n_tx_queues == 0) {
			continue;
		}

		printf ("%u (", port);
		for (queue = 0; queue < APP_MAX_TX_QUEUES_PER_NIC_PORT; queue++) {
			if (app.nic_tx_queue_mask[port][queue] == 1) {
				printf ("%u ", queue);
			}
		}
		printf (")  ");
	}
	printf (";\n");

	/* Print I/O lcore TX params */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;

		if ((app.lcore_params[lcore].type != e_APP_LCORE_IO) || (lp->tx.n_nic_queues == 0)) {
			continue;
		}

		printf ("I/O lcore %u (socket %u): ", lcore, rte_lcore_to_socket_id (lcore));

		printf ("TX ports  ");
		for (i = 0; i < lp->tx.n_nic_queues; i++) {
			printf ("(%u, %u)  ",
			        (unsigned)lp->tx.nic_queues[i].port,
			        (unsigned)lp->tx.nic_queues[i].queue);
		}
		printf (";\n");
	}

	/* Rings */
	printf ("Ring sizes: NIC RX = %u; NIC TX = %u;\n",
	        (unsigned)app.nic_rx_ring_size,
	        (unsigned)app.nic_tx_ring_size);

	/* Bursts */
	printf ("Burst sizes: I/O RX rd = %u; I/O TX wr = %u)\n",
	        (unsigned)app.burst_size_io_rx_read,
	        (unsigned)app.burst_size_io_tx_write);
}
