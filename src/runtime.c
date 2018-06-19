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
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
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
#include <rte_prefetch.h>
#include <rte_random.h>
#include <rte_ring.h>
#include <rte_tailq.h>
#include <rte_tcp.h>

#include "main.h"

#ifndef APP_LCORE_IO_FLUSH
#define APP_LCORE_IO_FLUSH 1000000
#endif

#ifndef APP_LCORE_WORKER_FLUSH
#define APP_LCORE_WORKER_FLUSH 1000000
#endif

#ifndef APP_STATS
#define APP_STATS 100000
#endif

#define APP_IO_RX_DROP_ALL_PACKETS 1
#define APP_WORKER_DROP_ALL_PACKETS 0
#define APP_IO_TX_DROP_ALL_PACKETS 0

#ifndef APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH_ENABLE 1
#endif

#ifndef APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH_ENABLE 1
#endif

#ifndef APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH_ENABLE 1
#endif

#if APP_IO_RX_PREFETCH_ENABLE
#define APP_IO_RX_PREFETCH0(p) rte_prefetch0 (p)
#define APP_IO_RX_PREFETCH1(p) rte_prefetch1 (p)
#else
#define APP_IO_RX_PREFETCH0(p)
#define APP_IO_RX_PREFETCH1(p)
#endif

#if APP_WORKER_PREFETCH_ENABLE
#define APP_WORKER_PREFETCH0(p) rte_prefetch0 (p)
#define APP_WORKER_PREFETCH1(p) rte_prefetch1 (p)
#else
#define APP_WORKER_PREFETCH0(p)
#define APP_WORKER_PREFETCH1(p)
#endif

#if APP_IO_TX_PREFETCH_ENABLE
#define APP_IO_TX_PREFETCH0(p) rte_prefetch0 (p)
#define APP_IO_TX_PREFETCH1(p) rte_prefetch1 (p)
#else
#define APP_IO_TX_PREFETCH0(p)
#define APP_IO_TX_PREFETCH1(p)
#endif

uint8_t caidaTrace    = 0;
char ethernetHeader[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x58, 0xBB, 0xCC, 0xDD, 0xEE, 0x58, 0x08, 0x00};

//#define QUEUE_STATS

// Prefetching mmap and atomics
static unsigned long lastregion = 0;
#define REGIONPRE (6 * 128 * 1024 * 1024ul)
#define REGIONMIN (REGIONPRE / 1)
#define REGIONMAX (REGIONPRE * 3)

static inline void app_lcore_io_rx (struct app_lcore_params_io *lp, uint32_t bsz_rd) {
	uint32_t i;

	for (i = 0; i < lp->rx.n_nic_queues; i++) {
		uint8_t port  = lp->rx.nic_queues[i].port;
		uint8_t queue = lp->rx.nic_queues[i].queue;
		uint32_t n_mbufs, j;

		n_mbufs = rte_eth_rx_burst (port, queue, lp->rx.mbuf_in.array, (uint16_t)bsz_rd);

		if (unlikely (n_mbufs == 0)) {
			continue;
		}

		for (j = 0; j < n_mbufs; j++) {
			struct rte_mbuf *pkt = lp->rx.mbuf_in.array[j];
			rte_pktmbuf_free (pkt);
		}
	}
}

#define DONOTRESEND
static __thread uint8_t numtxqueues = 0;

static inline void app_fill_1packet_frompcap (struct app_lcore_params_io *const restrict lp,
                                              const uint8_t port_id,
                                              const uint8_t queue_id,
                                              struct rte_mbuf *const restrict pkt) {
#ifdef DONOTRESEND
	unsigned muv;
	for (muv = 0; muv < lp->tx.n_nic_queues; muv++) {
#endif
		// get pointers
		uint8_t *pointer        = lp->tx.pcapfile_cur;
		pcaprec_hdr_tJZ *header = (pcaprec_hdr_tJZ *)pointer;
		uint8_t *data           = pointer + sizeof (pcaprec_hdr_tJZ);
		int len                 = header->orig_len;
		int caplen              = header->incl_len;

#ifdef DONOTRESEND
		if (muv == (numtxqueues % queue_id)) {
#endif
			char *pktptr = rte_pktmbuf_mtod (pkt, char *);

			if (caidaTrace) {
				len += sizeof (ethernetHeader);  // 10; //añadir longitud eth truncada
				rte_memcpy (pktptr, ethernetHeader, sizeof (ethernetHeader));
				pktptr += sizeof (ethernetHeader);
			}

			// copy data
			pkt->pkt_len  = len;
			pkt->data_len = len;
			pkt->port     = port_id;
			rte_memcpy (pktptr, data, caplen);

#ifdef DONOTRESEND
		}
#endif
		// move pointers
		lp->tx.pcapfile_cur += caplen + sizeof (pcaprec_hdr_tJZ);
		if (unlikely (lp->tx.pcapfile_cur == lp->tx.pcapfile_end)) {
			lp->tx.pcapfile_cur = lp->tx.pcapfile_start;
		}
#ifdef DONOTRESEND
	}
#endif
}

/*
long lastregion=0;
#define REGIONPRE (6*128*1024*1024l)
#define REGIONMIN (REGIONPRE/1)
#define REGIONMAX (REGIONPRE*3)
*/

static inline void app_fill_packets_frompcap (struct app_lcore_params_io *const restrict lp,
                                              const uint8_t port_id,
                                              const uint8_t queue_id,
                                              struct rte_mbuf *const restrict *const restrict pkts,
                                              const uint16_t nb_pkts) {
	int i;
	for (i = 0; i < nb_pkts; i++) {
		app_fill_1packet_frompcap (lp, port_id, queue_id, pkts[i]);
	}
	if (lp->tx.nic_queues[0].queue == 0) {
		uint64_t pos = lp->tx.pcapfile_cur - lp->tx.pcapfile_start;
		if (pos < REGIONMIN) {
			lastregion = 0;
		} else if ((pos + REGIONMAX - REGIONMIN) > lastregion) {
			// calc length
			unsigned char *addr =
			    lp->tx.pcapfile_start + ((pos / REGIONPRE) * REGIONPRE) - sizeof (pcap_hdr_tJZ);
			size_t length = (addr + REGIONMAX > lp->tx.pcapfile_end)
			                    ? (size_t) (lp->tx.pcapfile_end - addr)
			                    : REGIONMAX;

			lastregion += length;

			// do it
			if (madvise (addr, length, MADV_WILLNEED)) {
				perror ("madvise preload");
			}
		}
	}
}

static inline void app_lcore_io_tx (struct app_lcore_params_io *lp,
                                    uint32_t n_workers,
                                    uint32_t bsz_wr) {
	uint32_t worker;

	for (worker = 0; worker < n_workers; worker++) {
		uint32_t i;

		for (i = 0; i < lp->tx.n_nic_queues; i++) {
			uint8_t port  = lp->tx.nic_queues[i].port;
			uint8_t queue = lp->tx.nic_queues[i].queue;
			// struct rte_ring *ring = lp->tx.rings[port][worker];
			uint32_t n_pkts = 0;
			// int ret;

			// n_mbufs = lp->tx.mbuf_out[port].n_mbufs;
			/*ret = rte_ring_sc_dequeue_bulk(
			    ring,
			    (void **) &lp->tx.mbuf_out[port].array[n_mbufs],
			    bsz_rd);

			if (unlikely(ret == -ENOENT)) {
			    continue;
			}

			n_mbufs += bsz_rd;*/

			if (rte_pktmbuf_alloc_bulk (app.pools[0], lp->tx.mbuf_out[port].array, bsz_wr))
				continue;  // error

			app_fill_packets_frompcap (lp, port, queue, lp->tx.mbuf_out[port].array, bsz_wr);

			/*if (unlikely(n_mbufs < bsz_wr)) {
			    lp->tx.mbuf_out[port].n_mbufs = n_mbufs;
			    continue;
			}*/

			n_pkts = rte_eth_tx_burst (port, queue, lp->tx.mbuf_out[port].array, bsz_wr);

			while (unlikely (n_pkts < bsz_wr)) {
				n_pkts += rte_eth_tx_burst (
				    port, queue, lp->tx.mbuf_out[port].array + n_pkts, bsz_wr - n_pkts);
			}

#if APP_STATS
			lp->tx.nic_queues_iters[i]++;
			lp->tx.nic_queues_count[i] += n_pkts;
			if (unlikely (lp->tx.nic_queues_iters[i] == APP_STATS)) {
				struct rte_eth_stats stats;
				struct timeval start_ewr, end_ewr;

				rte_eth_stats_get (port, &stats);
				gettimeofday (&lp->tx.end_ewr, NULL);

				start_ewr = lp->tx.start_ewr;
				end_ewr   = lp->tx.end_ewr;

				if (queue == 0) {
					printf (
					    "NIC TX port %u: drop ratio = %.2f (%lu/%lu) usefull-speed: %lf Gbps, "
					    "link-speed: %lf Gbps (%.1lf pkts/s)\n",
					    (unsigned)port,
					    (double)stats.oerrors / (double)(stats.oerrors + stats.opackets),
					    (uint64_t)stats.opackets,
					    (uint64_t)stats.oerrors,
					    (stats.obytes / (((end_ewr.tv_sec * 1000000. + end_ewr.tv_usec) -
					                      (start_ewr.tv_sec * 1000000. + start_ewr.tv_usec)) /
					                     1000000.)) /
					        (1000 * 1000 * 1000. / 8.),
					    (((stats.obytes) + stats.opackets * (/*4crc+8prelud+12ifg*/ (8 + 12))) /
					     (((end_ewr.tv_sec * 1000000. + end_ewr.tv_usec) -
					       (start_ewr.tv_sec * 1000000. + start_ewr.tv_usec)) /
					      1000000.)) /
					        (1000 * 1000 * 1000. / 8.),
					    stats.opackets / (((end_ewr.tv_sec * 1000000. + end_ewr.tv_usec) -
					                       (start_ewr.tv_sec * 1000000. + start_ewr.tv_usec)) /
					                      1000000.));

					// rte_eth_stats_reset (port);
					// lp->tx.start_ewr = end_ewr;  // Updating start
				}

				lp->tx.nic_queues_iters[i] = 0;
				lp->tx.nic_queues_count[i] = 0;
			}
#endif
		}
	}
}

static void app_lcore_main_loop_io (void) {
	uint32_t lcore                 = rte_lcore_id ();
	struct app_lcore_params_io *lp = &app.lcore_params[lcore].io;
	uint64_t i                     = 0;

	numtxqueues = app_get_nic_tx_queues_per_port (lp->tx.nic_queues[0].port);
	gettimeofday (&lp->tx.start_ewr, NULL);

	for (;;) {
		/*if (APP_LCORE_IO_FLUSH && (unlikely(i == APP_LCORE_IO_FLUSH))) {
		    if (likely(lp->rx.n_nic_queues > 0)) {
		        app_lcore_io_rx_flush(lp, n_workers);
		    }
		    i = 0;
		}

		if (likely(lp->rx.n_nic_queues > 0)) {
		    app_lcore_io_rx(lp, n_workers, bsz_rx_rd, bsz_rx_wr, pos_lb);
		}*/

		if (likely (lp->tx.n_nic_queues > 0)) {
			app_lcore_io_tx (lp, 1, app.burst_size_io_tx_write);
		}

		i++;
	}
}

int app_lcore_main_loop (__attribute__ ((unused)) void *arg) {
	struct app_lcore_params *lp;
	unsigned lcore;

	lcore = rte_lcore_id ();
	lp    = &app.lcore_params[lcore];

	if (lp->type == e_APP_LCORE_IO) {
		printf ("Logical core %u (I/O) main loop.\n", lcore);
		app_lcore_main_loop_io ();
	}
	return 0;
}
