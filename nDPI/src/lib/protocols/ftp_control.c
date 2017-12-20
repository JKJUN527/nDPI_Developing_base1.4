/*
 * ftp_control.c
 *
 * Copyright (C) 2016 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocols.h"
#include "ndpi_utils.h"

#ifdef __KERNEL__
# define PRINT      printk
#else
# define PRINT      printf
#endif /* __KERNEL__ */

//#define LOCAL_DEBUG
#undef LOCAL_DEBUG

#undef _D
#ifdef LOCAL_DEBUG
# define _D(...)    PRINT(__VA_ARGS__)
#else
# define _D(...)    ((void)0)
#endif /* LOCAL_DEBUG */

#ifdef NDPI_PROTOCOL_FTP_CONTROL

static void ndpi_int_ftp_control_add_connection(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    //ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_FTP_CONTROL, NDPI_PROTOCOL_UNKNOWN);
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_FTP_CONTROL, NDPI_REAL_PROTOCOL);
}

static int ndpi_ftp_control_check_request(const u_int8_t *payload, size_t payload_len)
{
    struct string {
        char const *str;
        signed char len;
    } req_op [] = {
        { "PASV", 4 }, { "pasv", 4 }, { "PORT", 4 }, { "port", 4 }, { "TYPE", 4 },
        { "AUTH", 4 }, { "CCC",  3 }, { "CDUP", 4 }, { "CONF", 4 }, { "CWD",  3 },
        { "DELE", 4 }, { "ENC",  3 }, { "EPRT", 4 }, { "EPSV", 4 }, { "FEAT", 4 },
        { "HELP", 4 }, { "LANG", 4 }, { "LIST", 4 }, { "LPRT", 4 }, { "LPSV", 4 },
        { "MDTM", 4 }, { "MIC",  3 }, { "MKD",  3 }, { "MLSD", 4 }, { "MLST", 4 },
        { "MODE", 4 }, { "NLST", 4 }, { "NOOP", 4 }, { "OPTS", 4 }, { "PASS", 4 },
        { "ABOR", 4 }, { "PBSZ", 4 }, { "ADAT", 4 }, { "PROT", 4 }, { "PWD",  3 },
        { "QUIT", 4 }, { "REIN", 4 }, { "REST", 4 }, { "RETR", 4 }, { "RMD",  3 },
        { "RNFR", 4 }, { "RNTO", 4 }, { "SITE", 4 }, { "SIZE", 4 }, { "SMNT", 4 },
        { "STAT", 4 }, { "STOR", 4 }, { "STOU", 4 }, { "STRU", 4 }, { "SYST", 4 },
        { "APPE", 4 }, { "USER", 4 }, { "XCUP", 4 }, { "XMKD", 4 }, { "XPWD", 4 },
        { "XRCP", 4 }, { "XRMD", 4 }, { "XRSQ", 4 }, { "XSEM", 4 }, { "XSEN", 4 },
        { "HOST", 4 }, { "abor", 4 }, { "acct", 4 }, { "adat", 4 }, { "allo", 4 },
        { "appe", 4 }, { "auth", 4 }, { "ccc",  3 }, { "cdup", 4 }, { "conf", 4 },
        { "cwd",  3 }, { "dele", 4 }, { "enc",  3 }, { "eprt", 4 }, { "epsv", 4 },
        { "feat", 4 }, { "help", 4 }, { "lang", 4 }, { "list", 4 }, { "lprt", 4 },
        { "lpsv", 4 }, { "mdtm", 4 }, { "mic",  3 }, { "mkd",  3 }, { "mlsd", 4 },
        { "mlst", 4 }, { "mode", 4 }, { "nlst", 4 }, { "noop", 4 }, { "opts", 4 },
        { "pass", 4 }, { "ACCT", 4 }, { "pbsz", 4 }, { "ALLO", 4 }, { "prot", 4 },
        { "pwd",  3 }, { "quit", 4 }, { "rein", 4 }, { "rest", 4 }, { "retr", 4 },
        { "rmd",  3 }, { "rnfr", 4 }, { "rnto", 4 }, { "site", 4 }, { "size", 4 },
        { "smnt", 4 }, { "stat", 4 }, { "stor", 4 }, { "stou", 4 }, { "stru", 4 },
        { "syst", 4 }, { "type", 4 }, { "user", 4 }, { "xcup", 4 }, { "xmkd", 4 },
        { "xpwd", 4 }, { "xrcp", 4 }, { "xrmd", 4 }, { "xrsq", 4 }, { "xsem", 4 },
        { "xsen", 4 }, { "host", 4 },
    };

    int i;
    for (i = 0; i < sizeof(req_op)/sizeof(req_op[0]); i++) {
        if (payload_len >= req_op[i].len && !memcmp(payload, req_op[i].str, req_op[i].len)) {
            _D("FTP_CONTROL: found %s\n", req_op[i].str);
            return 1;
        }
    }
    return 0;
}

static int ndpi_ftp_control_check_response(const u_int8_t *payload, size_t payload_len)
{
    struct string {
        char const *str;
        signed char len;
    } res_code [] = {
        { "200 ", 4 },   { "211 ", 4 },   { "212 ", 4 },   { "213 ", 4 },   { "214 ", 4 },
        { "215 ", 4 },   { "220 ", 4 },   { "221 ", 4 },   { "225 ", 4 },   { "226 ", 4 },
        { "227 ", 4 },   { "228 ", 4 },   { "229 ", 4 },   { "230 ", 4 },   { "231 ", 4 },
        { "232 ", 4 },   { "250 ", 4 },   { "257 ", 4 },   { "331 ", 4 },   { "332 ", 4 },
        { "350 ", 4 },   { "421 ", 4 },   { "425 ", 4 },   { "426 ", 4 },   { "430 ", 4 },
        { "434 ", 4 },   { "450 ", 4 },   { "451 ", 4 },   { "452 ", 4 },   { "501 ", 4 },
        { "502 ", 4 },   { "503 ", 4 },   { "504 ", 4 },   { "530 ", 4 },   { "532 ", 4 },
        { "550 ", 4 },   { "551 ", 4 },   { "552 ", 4 },   { "553 ", 4 },   { "631 ", 4 },
        { "632 ", 4 },   { "633 ", 4 },   { "10054 ", 6 }, { "10060 ", 6 }, { "10061 ", 6 },
        { "110-", 4 },   { "120-", 4 },   { "125-", 4 },   { "150-", 4 },   { "202-", 4 },
        { "211-", 4 },   { "212-", 4 },   { "213-", 4 },   { "214-", 4 },   { "215-", 4 },
        { "220-", 4 },   { "221-", 4 },   { "225-", 4 },   { "226-", 4 },   { "227-", 4 },
        { "228-", 4 },   { "229-", 4 },   { "230-", 4 },   { "231-", 4 },   { "232-", 4 },
        { "250-", 4 },   { "257-", 4 },   { "331-", 4 },   { "332-", 4 },   { "350-", 4 },
        { "421-", 4 },   { "425-", 4 },   { "426-", 4 },   { "430-", 4 },   { "434-", 4 },
        { "450-", 4 },   { "451-", 4 },   { "452-", 4 },   { "501-", 4 },   { "502-", 4 },
        { "503-", 4 },   { "504-", 4 },   { "530-", 4 },   { "532-", 4 },   { "550-", 4 },
        { "551-", 4 },   { "552-", 4 },   { "553-", 4 },   { "631-", 4 },   { "632-", 4 },
        { "633-", 4 },   { "10054-", 6 }, { "10060-", 6 }, { "10061-", 6 }, { "10066-", 6 },
        { "10068-", 6 }, { "110 ", 4 },   { "120 ", 4 },   { "125 ", 4 },   { "150 ", 4 },
        { "10066 ", 6 }, { "10068 ", 6 }, { "202 ", 4 },   { "200-", 4},
    };

    int i;
    for (i = 0; i < sizeof(res_code)/sizeof(res_code[0]); i++) {
        if (payload_len >= res_code[i].len && !memcmp(payload, res_code[i].str, res_code[i].len)) {
            _D("FTP_CONTROL: found %s\n", res_code[i].str);
            return 1;
        }
    }
    return 0;
}

static void ftp_add_server_port_to_hash(struct ndpi_detection_module_struct *ndpi,
        struct ndpi_flow_struct *flow,
        u_int8_t const *_data, int len)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    int ipsize = sizeof(u_int32_t);
    u_int8_t *data = (u_int8_t*)_data;
    u_int8_t save = data[len-1];
    /* client ip, client port, server ip, server port, tcp/udp */
    u_int8_t key_buff[2*sizeof(u_int32_t) + 2*2 + 1] = {0}; /* set zero */

    int ip[4];
    int port[2];

    char const *p;
    int offset;

    /* TODO ftp_data: support ipv6 */
    /* Don't support ipv6 now */
    if (!packet->iph) return;

    data[len-1] = '\0';
    p = memfind(data, len, "(", 1);
    if (!p || (6 != sscanf(p, "(%d,%d,%d,%d,%d,%d)", ip, ip+1, ip+2, ip+3, port, port+1))) {
        data[len-1] = save;
        return;
    }
    data[len-1] = save;
    _D("FTP 227 %d,%d,%d,%d %d,%d\n", ip[0], ip[1], ip[2], ip[3], port[0], port[1]);

    offset = ipsize+2;
    /* store as networking order */
    key_buff[offset]   = 0xff & ip[0];
    key_buff[offset+1] = 0xff & ip[1];
    key_buff[offset+2] = 0xff & ip[2];
    key_buff[offset+3] = 0xff & ip[3];      /* server ip */
    offset += ipsize;
    key_buff[offset]   = 0xff & port[0];
    key_buff[offset+1] = 0xff & port[1];    /* server port */
    offset += 2;
    key_buff[offset] = IPPROTO_TCP;         /* tcp or udp */

    /* TODO consider add lock */
    ndpi_hash_add(ndpi->meta2protocol, key_buff, sizeof(key_buff), NDPI_PROTOCOL_FTP_DATA);
}

extern void ndpi_search_ftp_control(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
    struct ndpi_packet_struct *packet = &flow->packet;
    u_int32_t payload_len = packet->payload_packet_len;

    _D("FTP_CONTROL detection...\n");

    /* Check connection over TCP */
    if(!packet->tcp)
        return;

    /* Exclude SMTP, which uses similar commands. */
    if (packet->tcp->dest == htons(25) || packet->tcp->source == htons(25)) {
        _D("Exclude FTP_CONTROL.\n");
        NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FTP_CONTROL);
        return;
    }

    /* Check if we so far detected the protocol in the request or not. */
    _D("FTP_CONTROL stage %u:\n", flow->ftp_control_stage);
    switch (flow->ftp_control_stage) {
        /* First request */
    case 0:
        if (ndpi_ftp_control_check_request(packet->payload, payload_len)) {
            _D("Possible FTP_CONTROL request detected, we will look further for the response...\n");

            /* Encode the direction of the packet in the stage, so we will know when we need to look for the response packet. */
            flow->ftp_control_stage = 1;
            return;
        }
        break;

        /* First response */
    case 1:
        if (ndpi_ftp_control_check_response(packet->payload, payload_len)) {
            flow->ftp_control_stage = 2;
            _D("Found FTP_CONTROL in stage 1.\n");
            ndpi_int_ftp_control_add_connection(ndpi_struct, flow);
            return;
        }

        /* not ftp_control */
        _D("Exclude FTP_CONTROL in stage 1\n");
        NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_FTP_CONTROL);
        break;

        /* Wait for PORT and PASV command */
    case 2:
        if (payload_len > 4 && (!memcmp(packet->payload, "PASV", 4) || !memcmp(packet->payload, "pasv", 4))) {
            _D("Seen FTP_CONTROL PASV command.\n");
            flow->ftp_control_stage = 3;        /* goto parsing pasv response */
            return;
        }

        if (payload_len > 6 && ((!memcmp(packet->payload, "PORT", 4)) || !memcmp(packet->payload, "port", 4))) {
            _D("Found FTP_CONTROL via PORT command.\n");
            ndpi_int_ftp_control_add_connection(ndpi_struct, flow);
            return;
        }

        break;

        /* Parse PASV response */
    default:
        if (payload_len > 20 && !memcmp(packet->payload, "227 ", 4)) {
            /* parse server-port to hash table */
            ftp_add_server_port_to_hash(ndpi_struct, flow, packet->payload, payload_len);
            _D("Found FTP_CONTROL via PORT command.\n");
            ndpi_int_ftp_control_add_connection(ndpi_struct, flow);
            flow->ftp_control_stage = 2;
            return;
        }
    }
}

#endif
