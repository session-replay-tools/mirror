#ifndef TC_INCLUDED
#define TC_INCLUDED 
#include <xcopy.h>

typedef struct xcopy_clt_settings {
    unsigned int   mtu:16;               /* MTU sent to backend */
    unsigned int   mss:16;               /* MSS sent to backend */
    unsigned int   do_daemonize:1;       /* daemon flag */
    int            buffer_size;
    char          *raw_device;
    devices_t      devices;
    tc_pool_t     *pool;

    uint32_t       target_ip;
    unsigned char  smac[ETHER_ADDR_LEN];
    unsigned char  dmac[ETHER_ADDR_LEN];
    char          *raw_smac;
    char          *raw_dmac;
    char          *raw_target_ip;
    char          *user_filter;
    char          *output_if_name;
    char          *pid_file;             /* pid file */
    char          *log_path;             /* error log path */
    int            sig;  

    tc_event_t    *ev[MAX_FD_NUM];
    char           filter[MAX_FILTER_LENGH];
    unsigned char  pack_buffer[PCAP_RCV_BUF_SIZE];
 } xcopy_clt_settings;


extern tc_event_loop_t event_loop;
extern xcopy_clt_settings clt_settings;

#include <tc_util.h>

#include <tc_manager.h>
#include <tc_packets_module.h>

#endif /* TC_INCLUDED */
