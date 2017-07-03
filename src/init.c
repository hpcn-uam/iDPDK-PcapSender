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
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <numaif.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/stat.h>
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

static struct rte_eth_conf port_conf = {
    .rxmode =
        {
            .mq_mode        = ETH_MQ_RX_RSS,
            .max_rx_pkt_len = 9000,  // ETHER_MAX_JUMBO_FRAME_LEN,
            .split_hdr_size = 0,
            .header_split   = 0, /**< Header Split disabled */
            .hw_ip_checksum = 0,
            /**< IP checksum offload enabled */  // DISABLED!
            .hw_vlan_filter = 0,                 /**< VLAN filtering disabled */
            .jumbo_frame    = 1,
            /**< Jumbo Frame Support disabled */  // ENABLED!
            .hw_strip_crc = 0,                    /**< CRC stripped by hardware */
        },
    .rx_adv_conf =
        {
            .rss_conf =
                {
                    .rss_key = NULL, .rss_hf = ETH_RSS_IP,
                },
        },
    .txmode =
        {
            .mq_mode = ETH_MQ_TX_NONE,
        },
};

static struct rte_eth_rxconf rx_conf = {
    .rx_thresh =
        {
            .pthresh = APP_DEFAULT_NIC_RX_PTHRESH,
            .hthresh = APP_DEFAULT_NIC_RX_HTHRESH,
            .wthresh = APP_DEFAULT_NIC_RX_WTHRESH,
        },
    .rx_free_thresh = APP_DEFAULT_NIC_RX_FREE_THRESH,
    .rx_drop_en     = APP_DEFAULT_NIC_RX_DROP_EN,
};

static struct rte_eth_txconf tx_conf = {
    .tx_thresh =
        {
            .pthresh = APP_DEFAULT_NIC_TX_PTHRESH,
            .hthresh = APP_DEFAULT_NIC_TX_HTHRESH,
            .wthresh = APP_DEFAULT_NIC_TX_WTHRESH,
        },
    .tx_free_thresh = APP_DEFAULT_NIC_TX_FREE_THRESH,
    .tx_rs_thresh   = APP_DEFAULT_NIC_TX_RS_THRESH,
};

static void app_init_mbuf_pools (void) {
	unsigned socket, lcore;

	/* Init the buffer pools */
	for (socket = 0; socket < APP_MAX_SOCKETS; socket++) {
		char name[32];
		if (app_is_socket_used (socket) == 0) {
			continue;
		}

		snprintf (name, sizeof (name), "mbuf_pool_%u", socket);
		printf ("Creating the mbuf pool for socket %u ...\n", socket);
		app.pools[socket] = rte_mempool_create (name,
		                                        APP_DEFAULT_MEMPOOL_BUFFERS,
		                                        APP_DEFAULT_MBUF_SIZE,
		                                        APP_DEFAULT_MEMPOOL_CACHE_SIZE,
		                                        sizeof (struct rte_pktmbuf_pool_private),
		                                        rte_pktmbuf_pool_init,
		                                        NULL,
		                                        rte_pktmbuf_init,
		                                        NULL,
		                                        socket,
		                                        0);
		if (app.pools[socket] == NULL) {
			rte_panic ("Cannot create mbuf pool on socket %u\n", socket);
		}
	}

	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		if (app.lcore_params[lcore].type == e_APP_LCORE_DISABLED) {
			continue;
		}

		socket                       = rte_lcore_to_socket_id (lcore);
		app.lcore_params[lcore].pool = app.pools[socket];
	}
}

char pcap_File[256] = {0};

static void app_init_rings_tx (void) {
	unsigned lcore;

	/*Memory Node*/
	unsigned long nodemask = 1 << 0;//rte_lcore_to_socket_id (lcore);
	int ret                = set_mempolicy (MPOL_BIND, &nodemask, sizeof (nodemask) * 8);
	printf ("Binding mmap memory (mask: %016lx) => %d\n", nodemask, ret);

	/*Init pcap*/
	int fd = open (pcap_File, O_RDONLY);

	if (fd == -1) {
		perror ("pcap file");
		exit (-1);
	}

	struct stat sb;

	if (fstat (fd, &sb) == -1) {
		perror ("pcap file size unknown");
		exit (-1);
	}

	fprintf (stderr, "Preloading file...");
	fflush (stderr);

	void *pcapfile_start = mmap (NULL, sb.st_size, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd, 0);

	if (pcapfile_start == MAP_FAILED) {
		perror ("mmap failed");
		exit (-1);
	}

	fprintf (stderr, "Done!\n");
	fflush (stderr);

	/* Initialize the rings for the TX side */
	for (lcore = 0; lcore < APP_MAX_LCORES; lcore++) {
		unsigned port;

		for (port = 0; port < APP_MAX_NIC_PORTS; port++) {
			uint32_t lcore_io;

			if (app_get_nic_tx_queues_per_port (port) == 0) {
				continue;
			}

			if (app_get_lcore_for_nic_tx ((uint8_t)port, 0, &lcore_io) <
			    0) {  // TODO check other queues
				rte_panic (
				    "Algorithmic error (no I/O core to handle TX of port %u "
				    "and queue 0)\n",
				    port);
			}
			/*SetUp memory for current node*/
			struct app_lcore_params_io *lp_io = &app.lcore_params[lcore].io;
			lp_io->tx.pcapfile_start = pcapfile_start;

			lp_io->tx.pcapfile_end = lp_io->tx.pcapfile_start + sb.st_size;
			lp_io->tx.pcapfile_start += sizeof (pcap_hdr_tJZ);
			lp_io->tx.pcapfile_cur = lp_io->tx.pcapfile_start;
		}
	}
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void check_all_ports_link_status (uint8_t port_num, uint32_t port_mask) {
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint32_t n_rx_queues, n_tx_queues;

	printf ("\nChecking link status");
	fflush (stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			n_rx_queues = app_get_nic_rx_queues_per_port (portid);
			n_tx_queues = app_get_nic_tx_queues_per_port (portid);
			if ((n_rx_queues == 0) && (n_tx_queues == 0))
				continue;
			memset (&link, 0, sizeof (link));
			rte_eth_link_get (portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf (
					    "Port %d Link Up - speed %u "
					    "Mbps - %s\n",
					    (uint8_t)portid,
					    (unsigned)link.link_speed,
					    (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex")
					                                               : ("half-duplex\n"));
				else
					printf ("Port %d Link Down\n", (uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf (".");
			fflush (stdout);
			rte_delay_ms (CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf ("done\n");
		}
	}
}

static void app_init_nics (void) {
	unsigned socket;
	uint32_t lcore = 0;
	uint8_t port, queue;
	int ret;
	uint32_t n_rx_queues, n_tx_queues;

	/* Init NIC ports and queues, then start the ports */
	for (port = 0; port < APP_MAX_NIC_PORTS; port++) {
		struct rte_mempool *pool;

		n_rx_queues = app_get_nic_rx_queues_per_port (port);
		n_tx_queues = app_get_nic_tx_queues_per_port (port);

		if ((n_rx_queues == 0) && (n_tx_queues == 0)) {
			continue;
		}

		/* Init port */
		printf ("Initializing NIC port %u ...\n", (unsigned)port);
		ret = rte_eth_dev_configure (port, (uint8_t)n_rx_queues, (uint8_t)n_tx_queues, &port_conf);
		if (ret < 0) {
			rte_panic ("Cannot init NIC port %u (%d)\n", (unsigned)port, ret);
		}
		rte_eth_promiscuous_enable (port);

		/* Init RX queues */
		for (queue = 0; queue < APP_MAX_RX_QUEUES_PER_NIC_PORT; queue++) {
			if (app.nic_rx_queue_mask[port][queue] == 0) {
				continue;
			}

			app_get_lcore_for_nic_rx (port, queue, &lcore);
			socket = rte_lcore_to_socket_id (lcore);
			pool   = app.lcore_params[lcore].pool;

			printf ("Initializing NIC port %u RX queue %u ...\n", (unsigned)port, (unsigned)queue);
			ret = rte_eth_rx_queue_setup (
			    port, queue, (uint16_t)app.nic_rx_ring_size, socket, &rx_conf, pool);
			if (ret < 0) {
				rte_panic ("Cannot init RX queue %u for port %u (%d)\n",
				           (unsigned)queue,
				           (unsigned)port,
				           ret);
			}
		}

		/* Init TX queues */
		for (queue = 0; queue < APP_MAX_TX_QUEUES_PER_NIC_PORT; queue++) {
			if (app.nic_tx_queue_mask[port][queue] == 0) {
				continue;
			}

			app_get_lcore_for_nic_tx (port, queue, &lcore);
			socket = rte_lcore_to_socket_id (lcore);

			printf ("Initializing NIC port %u TX queue %u ...\n", (unsigned)port, (unsigned)queue);
			ret = rte_eth_tx_queue_setup (
			    port, queue, (uint16_t)app.nic_tx_ring_size, socket, &tx_conf);
			if (ret < 0) {
				rte_panic ("Cannot init TX queue %u for port %u (%d)\n",
				           (unsigned)queue,
				           (unsigned)port,
				           ret);
			}
		}

		/* Start port */
		ret = rte_eth_dev_start (port);
		if (ret < 0) {
			rte_panic ("Cannot start port %d (%d)\n", port, ret);
		}
	}

	check_all_ports_link_status (APP_MAX_NIC_PORTS, (~0x0));
}

void app_init (void) {
	app_init_mbuf_pools ();
	// app_init_rings_rx ();
	app_init_rings_tx ();
	app_init_nics ();

	// HPTL
	hptl_config conf = {.clockspeed = 0, .precision = 9};
	hptl_init (&conf);

	printf ("Using HPTL %s.\n", hptl_VERSION);

	printf ("Initialization completed.\n");
}
