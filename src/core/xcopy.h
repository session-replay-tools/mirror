#ifndef  XCOPY_H_INCLUDED
#define  XCOPY_H_INCLUDED

#include <tc_auto_config.h>
#include <limits.h>
#include <asm/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#include <pcap.h>

#define VERSION "1.0.0"  

typedef struct tc_pool_s        tc_pool_t;


#define ETHER_ADDR_LEN 0x6

#ifndef TC_CPU_CACHE_LINE
#define TC_CPU_CACHE_LINE  64
#endif

#ifdef TC_HAVE_PF_RING
#define PCAP_RCV_BUF_SIZE 8192
#else
#define PCAP_RCV_BUF_SIZE 65535
#endif
#define IP_BUF_SIZE (PCAP_RCV_BUF_SIZE - ETHERNET_HDR_LEN)
#define MAX_FILTER_LENGH 4096 

#define TC_PCAP_BUF_SIZE 16777216

#define TC_MAX_ALLOC_FROM_POOL  (tc_pagesize - 1)


#define TC_POOL_ALIGNMENT       16

#define TC_MIN_POOL_SIZE                                                         \
        tc_align((sizeof(tc_pool_t) + 2 * sizeof(tc_pool_large_t)),              \
                              TC_POOL_ALIGNMENT)

#define DEFAULT_MTU   1500
#define DEFAULT_MSS   1460
#define MAX_CHECKED_MTU 2048

#define CHECK_INTERVAL  5

#define TC_DEFAULT_POOL_SIZE   (16 * 1024)

#define MAX_FD_NUM    1024
#define MAX_FD_VALUE  (MAX_FD_NUM - 1)

#define MAX_DEVICE_NUM 32
#define MAX_DEVICE_NAME_LEN 32

typedef volatile sig_atomic_t tc_atomic_t;

typedef struct iphdr  tc_iph_t;
typedef struct tcphdr tc_tcph_t;

/* bool constants */
#if (HAVE_STDBOOL_H)
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif /* HAVE_STDBOOL_H */ 


#define ETHER_ADDR_STR_LEN 17

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100  /* IEEE 802.1Q VLAN tagging */
#endif

#define CISCO_HDLC_LEN 4
#define SLL_HDR_LEN 16
#define ETHERNET_HDR_LEN (sizeof(struct ethernet_hdr))
#define DEFAULT_DEVICE     "any"

/*  
 *  Ethernet II header
 *  static header size: 14 bytes          
 */ 
struct ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;                 
};


typedef struct device_s{
    char    name[MAX_DEVICE_NAME_LEN];
    pcap_t *pcap;
}device_t;

typedef struct devices_s{
    int       device_num;
    device_t  device[MAX_DEVICE_NUM];
}devices_t;

/* global functions */
int daemonize(void);


#define TC_OK      0
#define TC_ERR    -1
#define TC_ERR_EXIT  1
#define TC_DELAYED  -2

#define tc_cpymem(d, s, l) (((char *) memcpy(d, (void *) s, l)) + (l))
#define tc_memzero(d, l) (memset(d, 0, l))

#define tc_abs(value)       (((value) >= 0) ? (value) : - (value))
#define tc_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define tc_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))
#define tc_string(str)     { sizeof(str) - 1, (u_char *) str }

#include <tc_config.h>
#include <tc_time.h>
#include <tc_rbtree.h>
#include <tc_signal.h>

#include <tc_log.h>
#include <tc_socket.h>
#include <tc_util.h>
#include <tc_alloc.h>
#include <tc_palloc.h>
#include <tc_event.h>
#include <tc_select_module.h>
#include <tc_event_timer.h>

#endif /* XCOPY_H_INCLUDED */

