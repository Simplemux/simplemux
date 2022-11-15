/*
 * Copyright 2010,2011,2012,2013,2014 Didier Barvaux
 * Copyright 2012 Viveris Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * @file   test_empty_payload.c
 * @brief  Check that IP/ROHC packets with empty payloads are correctly
 *         compressed/decompressed
 * @author Didier Barvaux <didier@barvaux.org>
 *
 * The application compresses IP packets from a source PCAP file, check that
 * the last compressed packet is of the expected type (IR, IR-DYN...) and
 * decompresses all the generated ROHC packets. All IP packets should be
 * correctly compressed. All generated ROHC packets should be correctly
 * decompressed.
 */

#include "test.h"
#include "config.h" /* for HAVE_*_H */

/* system includes */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#if HAVE_WINSOCK2_H == 1
#  include <winsock2.h> /* for ntohs() on Windows */
#endif
#if HAVE_ARPA_INET_H == 1
#  include <arpa/inet.h> /* for ntohs() on Linux */
#endif
#include <errno.h>
#include <assert.h>
#include <time.h> /* for time(2) */
#include <stdarg.h>

/* includes for network headers */
#include <protocols/ipv4.h>
#include <protocols/ipv6.h>

/* include for the PCAP library */
#if HAVE_PCAP_PCAP_H == 1
#  include <pcap/pcap.h>
#elif HAVE_PCAP_H == 1
#  include <pcap.h>
#else
#  error "pcap.h header not found, did you specified --enable-rohc-tests \
for ./configure ? If yes, check configure output and config.log"
#endif

/* ROHC includes */
#include <rohc.h>
#include <rohc_comp.h>
#include <rohc_decomp.h>
#include <rohc_packets.h>


/* prototypes of private functions */
static void usage(void);
static int test_comp_and_decomp(const char *filename,
                                const unsigned int profile_id,
                                const rohc_packet_t expected_packet);
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
	__attribute__((format(printf, 5, 6), nonnull(5)));
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
	__attribute__((nonnull(1)));
static bool rohc_comp_rtp_cb(const unsigned char *const ip,
                             const unsigned char *const udp,
                             const unsigned char *const payload,
                             const unsigned int payload_size,
                             void *const rtp_private)
	__attribute__((warn_unused_result));


/**
 * @brief Check that IP/ROHC packets with empty payloads are correctly
 *        compressed/decompressed
 *
 * @param argc The number of program arguments
 * @param argv The program arguments
 * @return     The unix return code:
 *              \li 0 in case of success,
 *              \li 1 in case of failure
 */
int main(int argc, char *argv[])
{
	char *filename = NULL;
	char *profile_name = NULL;
	unsigned int profile_id;
	char *packet_type = NULL;
	rohc_packet_t expected_packet;
	int status = 1;

	/* parse program arguments, print the help message in case of failure */
	if(argc <= 3)
	{
		usage();
		goto error;
	}

	for(argc--, argv++; argc > 0; argc--, argv++)
	{
		if(!strcmp(*argv, "-h"))
		{
			/* print help */
			usage();
			goto error;
		}
		else if(filename == NULL)
		{
			/* get the name of the file that contains the packets to
			 * compress/decompress */
			filename = argv[0];
		}
		else if(profile_name == NULL)
		{
			/* get the name of the profile to enable ('auto' means all) */
			profile_name = argv[0];
		}
		else if(packet_type == NULL)
		{
			/* get the expected type of the last packet of the capture */
			packet_type = argv[0];
		}
		else
		{
			/* do not accept more than two arguments without option name */
			usage();
			goto error;
		}
	}

	/* the source filename, the profile name and the packet type are mandatory */
	if(filename == NULL || profile_name == NULL || packet_type == NULL)
	{
		usage();
		goto error;
	}

	/* parse the profile name */
	if(strcmp(profile_name, "uncompressedprofile") == 0)
	{
		profile_id = ROHC_PROFILE_UNCOMPRESSED;
	}
	else if(strcmp(profile_name, "iponlyprofile") == 0)
	{
		profile_id = ROHC_PROFILE_IP;
	}
	else if(strcmp(profile_name, "udpprofile") == 0)
	{
		profile_id = ROHC_PROFILE_UDP;
	}
	else if(strcmp(profile_name, "udpliteprofile") == 0)
	{
		profile_id = ROHC_PROFILE_UDPLITE;
	}
	else if(strcmp(profile_name, "rtpprofile") == 0)
	{
		profile_id = ROHC_PROFILE_RTP;
	}
	else if(strcmp(profile_name, "espprofile") == 0)
	{
		profile_id = ROHC_PROFILE_ESP;
	}
	else if(strcmp(profile_name, "auto") == 0)
	{
		profile_id = 0xFFFF;
	}
	else
	{
		fprintf(stderr, "unknown profile '%s'\n", profile_name);
		usage();
		goto error;
	}

	/* parse the packet type */
	if(strcmp(packet_type, "ir") == 0)
	{
		expected_packet = ROHC_PACKET_IR;
	}
	else if(strcmp(packet_type, "irdyn") == 0)
	{
		expected_packet = ROHC_PACKET_IR_DYN;
	}
	else if(strcmp(packet_type, "uo0") == 0)
	{
		expected_packet = ROHC_PACKET_UO_0;
	}
	else if(strcmp(packet_type, "uo1") == 0)
	{
		expected_packet = ROHC_PACKET_UO_1_TS;
	}
	else if(strcmp(packet_type, "uor2") == 0)
	{
		expected_packet = ROHC_PACKET_UOR_2_TS;
	}
	else
	{
		fprintf(stderr, "unknown packet type '%s'\n", packet_type);
		usage();
		goto error;
	}

	/* test ROHC compression/decompression with the packets from the file */
	status = test_comp_and_decomp(filename, profile_id, expected_packet);

error:
	return status;
}


/**
 * @brief Print usage of the application
 */
static void usage(void)
{
	fprintf(stderr,
	        "Check that IP/ROHC packets with empty payloads are correctly\n"
	        "compressed/decompressed\n"
	        "\n"
	        "usage: test_empty_payload [OPTIONS] FLOW PACKET_TYPE\n"
	        "\n"
	        "with:\n"
	        "  FLOW          The flow of Ethernet frames to compress\n"
	        "                (in PCAP format)\n"
	        "  PROFILE_NAME  The name of the profile to enable ('auto' means all)\n"
	        "  PACKET_TYPE   The packet type expected for the last packet\n"
	        "                among: ir, irdyn, uo0, uo1, uor2\n"
	        "\n"
	        "options:\n"
	        "  -h           Print this usage and exit\n");
}


/**
 * @brief Test the ROHC library with a flow of IP packets with empty payload
 *        going through one compressor then one decompressor
 *
 * @param filename         The name of the PCAP file that contains the
 *                         IP packets
 * @param profile_id       The profile to compress packets with
 *                         (0xFFFF means all)
 * @param expected_packet  The type of ROHC packet expected at the end of the
 *                         source capture
 * @return                 0 in case of success,
 *                         1 in case of failure
 */
static int test_comp_and_decomp(const char *filename,
                                const unsigned int profile_id,
                                const rohc_packet_t expected_packet)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int link_layer_type;
	int link_len;

	struct rohc_comp *comp;
	struct rohc_decomp *decomp;
	rohc_packet_t last_packet_type = ROHC_PACKET_UNKNOWN;

	struct pcap_pkthdr header;
	unsigned char *packet;
	unsigned int counter;

	int is_failure = 1;

	/* open the source dump file */
	handle = pcap_open_offline(filename, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "failed to open the source pcap file: %s\n", errbuf);
		goto error;
	}

	/* link layer in the source dump must be Ethernet */
	link_layer_type = pcap_datalink(handle);
	if(link_layer_type != DLT_EN10MB &&
	   link_layer_type != DLT_LINUX_SLL &&
	   link_layer_type != DLT_RAW)
	{
		fprintf(stderr, "link layer type %d not supported in source dump "
		        "(supported = %d, %d, %d)\n", link_layer_type,
		        DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW);
		goto close_input;
	}

	/* determine the length of the link layer header */
	if(link_layer_type == DLT_EN10MB)
	{
		link_len = ETHER_HDR_LEN;
	}
	else if(link_layer_type == DLT_LINUX_SLL)
	{
		link_len = LINUX_COOKED_HDR_LEN;
	}
	else /* DLT_RAW */
	{
		link_len = 0;
	}

	/* initialize the random generator */
	srand(time(NULL));

	/* create the ROHC compressor with small CID */
	comp = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX,
	                      gen_random_num, NULL);
	if(comp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC compressor\n");
		goto close_input;
	}

	/* set the callback for traces on compressor */
	if(!rohc_comp_set_traces_cb2(comp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "failed to set the callback for traces on "
		        "compressor\n");
		goto destroy_comp;
	}

	/* enable the requested profile(s) */
	if(profile_id != 0xFFFF)
	{
		fprintf(stderr, "enable only the compression profile %u\n", profile_id);
		if(!rohc_comp_enable_profile(comp, profile_id))
		{
			fprintf(stderr, "failed to enable the compression profile\n");
			goto destroy_comp;
		}
	}
	else
	{
		fprintf(stderr, "enable all compression profiles\n");
		if(!rohc_comp_enable_profiles(comp, ROHC_PROFILE_UNCOMPRESSED,
		                              ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
		                              ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
		                              ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
		{
			fprintf(stderr, "failed to enable the compression profiles\n");
			goto destroy_comp;
		}
	}

	/* set UDP ports dedicated to RTP traffic */
	if(!rohc_comp_set_rtp_detection_cb(comp, rohc_comp_rtp_cb, NULL))
	{
		fprintf(stderr, "failed to set the callback RTP detection\n");
		goto destroy_comp;
	}

	/* create the ROHC decompressor in unidirectional mode */
	decomp = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, ROHC_U_MODE);
	if(decomp == NULL)
	{
		fprintf(stderr, "failed to create the ROHC decompressor\n");
		goto destroy_comp;
	}

	/* set the callback for traces on decompressor */
	if(!rohc_decomp_set_traces_cb2(decomp, print_rohc_traces, NULL))
	{
		fprintf(stderr, "cannot set trace callback for decompressor\n");
		goto destroy_decomp;
	}

	/* enable decompression profiles */
	if(!rohc_decomp_enable_profiles(decomp, ROHC_PROFILE_UNCOMPRESSED,
	                                ROHC_PROFILE_UDP, ROHC_PROFILE_IP,
	                                ROHC_PROFILE_UDPLITE, ROHC_PROFILE_RTP,
	                                ROHC_PROFILE_ESP, ROHC_PROFILE_TCP, -1))
	{
		fprintf(stderr, "failed to enable the decompression profiles\n");
		goto destroy_decomp;
	}

	/* for each packet in the dump */
	counter = 0;
	while((packet = (unsigned char *) pcap_next(handle, &header)) != NULL)
	{
		const struct rohc_ts arrival_time = { .sec = 0, .nsec = 0 };
		rohc_comp_last_packet_info2_t last_packet_info;
		struct rohc_buf ip_packet =
			rohc_buf_init_full(packet, header.caplen, arrival_time);
		uint8_t rohc_buffer[MAX_ROHC_SIZE];
		struct rohc_buf rohc_packet =
			rohc_buf_init_empty(rohc_buffer, MAX_ROHC_SIZE);
		uint8_t decomp_buffer[MAX_ROHC_SIZE];
		struct rohc_buf decomp_packet =
			rohc_buf_init_empty(decomp_buffer, MAX_ROHC_SIZE);
		rohc_status_t status;

		counter++;

		fprintf(stderr, "packet #%u:\n", counter);

		/* check the length of the link layer header/frame */
		if(header.len <= link_len || header.len != header.caplen)
		{
			fprintf(stderr, "\ttruncated packet in capture (len = %d, "
			        "caplen = %d)\n", header.len, header.caplen);
			goto destroy_decomp;
		}

		/* skip the link layer header */
		rohc_buf_pull(&ip_packet, link_len);

		/* check for padding after the IP packet in the Ethernet payload */
		if(link_len == ETHER_HDR_LEN && header.len == ETHER_FRAME_MIN_LEN)
		{
			uint8_t version;
			uint16_t tot_len;

			/* get IP version */
			version = (rohc_buf_byte(ip_packet) >> 4) & 0x0f;

			/* get IP total length depending on IP version */
			if(version == 4)
			{
				struct ipv4_hdr *ip = (struct ipv4_hdr *) rohc_buf_data(ip_packet);
				tot_len = ntohs(ip->tot_len);
			}
			else
			{
				struct ipv6_hdr *ip = (struct ipv6_hdr *) rohc_buf_data(ip_packet);
				tot_len = sizeof(struct ipv6_hdr) + ntohs(ip->ip6_plen);
			}

			/* determine if there is Ethernet padding after IP packet */
			if(tot_len < ip_packet.len)
			{
				/* there is Ethernet padding, ignore these bits because there are
				 * not part of the IP packet */
				ip_packet.len = tot_len;
			}
		}
		fprintf(stderr, "\tpacket is valid\n");

		/* compress the IP packet with the ROHC compressor */
		status = rohc_compress4(comp, ip_packet, &rohc_packet);
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "\tfailed to compress IP packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tcompression is successful\n");

		/* get packet statistics and remember the packet type */
		last_packet_info.version_major = 0;
		last_packet_info.version_minor = 0;
		if(!rohc_comp_get_last_packet_info2(comp, &last_packet_info))
		{
			fprintf(stderr, "\tfailed to get statistics on packet\n");
			goto destroy_decomp;
		}
		last_packet_type = last_packet_info.packet_type;
		fprintf(stderr, "\tROHC packet of type '%s' (%d) generated\n",
		        rohc_get_packet_descr(last_packet_type), last_packet_type);

		/* decompress the generated ROHC packet with the ROHC decompressor */
		status = rohc_decompress3(decomp, rohc_packet, &decomp_packet,
		                          NULL, NULL);
		if(status != ROHC_STATUS_OK)
		{
			fprintf(stderr, "\tfailed to decompress generated ROHC packet\n");
			goto destroy_decomp;
		}
		fprintf(stderr, "\tdecompression is successful\n");
	}

	/* is the last packet of the expected type? */
	if(last_packet_type != expected_packet)
	{
		fprintf(stderr, "last generated ROHC packet is not as expected: "
		        "packet type '%s' (%d) generated while '%s' (%d) expected\n",
		        rohc_get_packet_descr(last_packet_type), last_packet_type,
		        rohc_get_packet_descr(expected_packet), expected_packet);
		goto destroy_decomp;
	}

	/* everything went fine */
	fprintf(stderr, "last generated ROHC packet is of type '%s' (%d) as "
	        "expected\n", rohc_get_packet_descr(expected_packet),
	        expected_packet);
	is_failure = 0;

destroy_decomp:
	rohc_decomp_free(decomp);
destroy_comp:
	rohc_comp_free(comp);
close_input:
	pcap_close(handle);
error:
	return is_failure;
}


/**
 * @brief Callback to print traces of the ROHC library
 *
 * @param priv_ctxt  An optional private context, may be NULL
 * @param level      The priority level of the trace
 * @param entity     The entity that emitted the trace among:
 *                    \li ROHC_TRACE_COMP
 *                    \li ROHC_TRACE_DECOMP
 * @param profile    The ID of the ROHC compression/decompression profile
 *                   the trace is related to
 * @param format     The format string of the trace
 */
static void print_rohc_traces(void *const priv_ctxt,
                              const rohc_trace_level_t level,
                              const rohc_trace_entity_t entity,
                              const int profile,
                              const char *const format,
                              ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
}


/**
 * @brief Generate a random number
 *
 * @param comp          The ROHC compressor
 * @param user_context  Should always be NULL
 * @return              A random number
 */
static int gen_random_num(const struct rohc_comp *const comp,
                          void *const user_context)
{
	assert(comp != NULL);
	assert(user_context == NULL);
	return rand();
}


/**
 * @brief The RTP detection callback
 *
 * @param ip           The innermost IP packet
 * @param udp          The UDP header of the packet
 * @param payload      The UDP payload of the packet
 * @param payload_size The size of the UDP payload (in bytes)
 * @param rtp_private  An optional private context
 * @return             true if the packet is an RTP packet, false otherwise
 */
static bool rohc_comp_rtp_cb(const unsigned char *const ip __attribute__((unused)),
                             const unsigned char *const udp,
                             const unsigned char *const payload __attribute__((unused)),
                             const unsigned int payload_size __attribute__((unused)),
                             void *const rtp_private __attribute__((unused)))
{
	const size_t default_rtp_ports_nr = 5;
	unsigned int default_rtp_ports[] = { 1234, 36780, 33238, 5020, 5002 };
	uint16_t udp_dport;
	bool is_rtp = false;
	size_t i;

	if(udp == NULL)
	{
		return false;
	}

	/* get the UDP destination port */
	memcpy(&udp_dport, udp + 2, sizeof(uint16_t));

	/* is the UDP destination port in the list of ports reserved for RTP
	 * traffic by default (for compatibility reasons) */
	for(i = 0; i < default_rtp_ports_nr; i++)
	{
		if(ntohs(udp_dport) == default_rtp_ports[i])
		{
			is_rtp = true;
			break;
		}
	}

	return is_rtp;
}

