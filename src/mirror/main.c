/*
 *  mirror 1.0 
 *
 *  Mirror packets to a target server
 *
 *  Copyright 2014 Netease, Inc.  All rights reserved.
 *  Use and distribution licensed under the BSD license.
 *  See the LICENSE file for full text.
 *
 *  Authors:
 *      Bin Wang <wangbin579@gmail.com>
 */

#include <xcopy.h>
#include <mirror.h>

tc_event_loop_t    event_loop;
xcopy_clt_settings clt_settings;


static void
usage(void)
{
    printf("mirror " VERSION "\n");
    printf("-s <mac_addr>  the MAC address of the interface where packets are going out\n");
    printf("-t <mac_addr>  the target MAC address which is also the next hop's MAC address\n");
    printf("-x <ip_addr>   change the destination ip address of the packet.\n"
           "               You could use any IP address except the online server's IP address\n"
           "               and the target server's IP address.\n");
    printf("-i <device,>   The name of the interface to listen on. This is usually a driver\n"
           "               name followed by a unit number, for example eth0 for the first\n"
           "               Ethernet interface.\n");
    printf("-F <filter>    use filter (same as pcap filter) to capture ingress packets.\n"
           "               Don't capture all packets or the packets which are sent by mirror itself\n");
    printf("-B <num>       buffer size for pcap capture in megabytes(default 16M)\n");
    printf("-o <device,>   The name of the interface to send. This is usually a driver\n"
           "               name followed by a unit number, for example eth0 for the first\n"
           "               Ethernet interface.\n");
    printf("-M <num>       MTU value sent to backend (default 1500)\n");
    printf("-D <num>       MSS value sent back(default 1460)\n");
    printf("-S <snaplen>   capture <snaplen> bytes per packet\n");
    printf("-l <file>      save the log information in <file>\n");
    printf("-P <file>      save PID in <file>, only used with -d option\n");
    printf("-h             print this help and exit\n"
           "-v             version\n"
           "-d             run as a daemon\n");
}


static unsigned char 
char_to_data(const char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0'; 
    }    

    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }    

    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 10;
    }    

    return 0;
}

static int 
convert_str_to_mac(unsigned char *dmac, char *raw_mac)
{
    int            i, len;
    char          *p;
    
    p = raw_mac;

    len = strlen(p);
    if (len < ETHER_ADDR_STR_LEN) {
        tc_log_info(LOG_WARN, 0, "mac address is too short:%d", len);
        return -1;
    }

    for (i = 0; i < ETHER_ADDR_LEN; ++i) {
        dmac[i]  = char_to_data(*p++) << 4;
        dmac[i] += char_to_data(*p++);
        p++;
    }

    return 0;
}

static int
read_args(int argc, char **argv)
{
    int  c;

    opterr = 0;
    while (-1 != (c = getopt(argc, argv,
         "s:" 
         "t:" 
         "x:" 
         "i:" /* <device,> */
         "F:" /* <filter> */
         "B:" 
         "o:" /* <device,> */
         "M:" /* MTU sent to backend */
         "D:" /* mss value sent to backend */
         "S:" 
         "l:" /* error log file */
         "P:" /* save PID in file */
         "h"  /* help, licence info */
         "v"  /* version */
         "d"  /* daemon mode */
        ))) {
        switch (c) {
            case 's':
                clt_settings.raw_smac = optarg;
                break;
            case 't':
                clt_settings.raw_dmac = optarg;
                break;
            case 'x':
                clt_settings.raw_target_ip = optarg;
                break;
            case 'o':
                clt_settings.output_if_name = optarg;
                break;
            case 'i':
                clt_settings.raw_device = optarg;
                break;
            case 'F':
                clt_settings.user_filter = optarg;
                break;
            case 'B':
                clt_settings.buffer_size = 1024 * 1024 * atoi(optarg);
                break;
            case 'l':
                clt_settings.log_path = optarg;
                break;
            case 'M':
                clt_settings.mtu = atoi(optarg);
                break;
            case 'D':
                clt_settings.mss = atoi(optarg);
                break;
            case 'S':
                clt_settings.snaplen = atoi(optarg);
                break;
            case 'h':
                usage();
                return -1;
            case 'v':
                printf ("mirror version:%s\n", VERSION);
                return -1;
            case 'd':
                clt_settings.do_daemonize = 1;
                break;
            case 'P':
                clt_settings.pid_file = optarg;
                break;
            case '?':
                switch (optopt) {    
                    case 's':
                        fprintf(stderr, "mirror: option -%c require a mac address\n", 
                                optopt);
                        break;
                    case 't':
                        fprintf(stderr, "mirror: option -%c require a mac address\n", 
                                optopt);
                        break;
                    case 'x':
                        fprintf(stderr, "mirror: option -%c require a ip address\n", 
                                optopt);
                        break;
                    case 'l':
                    case 'P':
                        fprintf(stderr, "mirror: option -%c require a file name\n", 
                                optopt);
                        break;
                    case 'i':
                        fprintf(stderr, "mirror: option -%c require a device name\n",
                                optopt);
                        break;
                    case 'o':
                        fprintf(stderr, "mirror: option -%c require a device name\n",
                                optopt);
                        break;
                    case 'B':
                    case 'M':
                    case 'D':
                    case 'S':
                        fprintf(stderr, "mirror: option -%c require a number\n",
                                optopt);
                        break;

                    default:
                        fprintf(stderr, "mirror: illegal argument \"%c\"\n",
                                optopt);
                        break;
                }
                return -1;

            default:
                fprintf(stderr, "mirror: illegal argument \"%c\"\n", optopt);
                return -1;
        }
    }

    return 0;
}

static void
output_for_debug()
{
    /* print out version info */
    tc_log_info(LOG_NOTICE, 0, "mirror version:%s", VERSION);

#if (HAVE_SET_IMMEDIATE_MODE)
    tc_log_info(LOG_NOTICE, 0, "HAVE_SET_IMMEDIATE_MODE is true");
#endif
#if (TC_HAVE_PF_RING)
    tc_log_info(LOG_NOTICE, 0, "TC_HAVE_PF_RING is true");
#endif
}


static int
set_details()
{
    int len;

    if (clt_settings.output_if_name != NULL) {
        tc_log_info(LOG_NOTICE, 0, "output device:%s", 
                clt_settings.output_if_name);
    } else {
        tc_log_info(LOG_ERR, 0, "no -o argument");
        fprintf(stderr, "no -o argument\n");
        return -1;
    }

    if (clt_settings.raw_device != NULL) {
        tc_log_info(LOG_NOTICE, 0, "device:%s", clt_settings.raw_device);
        if (strcmp(clt_settings.raw_device, DEFAULT_DEVICE) == 0) {
            clt_settings.raw_device = NULL; 
        } else {
            retrieve_devices(clt_settings.raw_device, &(clt_settings.devices));
        }
    }

    if (clt_settings.raw_target_ip != NULL) {
        tc_log_info(LOG_NOTICE, 0, "target ip:%s", clt_settings.raw_target_ip);
        clt_settings.target_ip = inet_addr(clt_settings.raw_target_ip);
    } else {
        if (clt_settings.raw_device == NULL || 
                clt_settings.devices.device_num > 1 || 
                !strcmp(clt_settings.raw_device, clt_settings.output_if_name)) 
        {
            tc_log_info(LOG_ERR, 0, "no -x argument");
            fprintf(stderr, "set the target ip\n");
            return -1;
        }
        
        tc_log_info(LOG_WARN, 0, "be caution: no -x argument");
    }

    if (clt_settings.snaplen > PCAP_RCV_BUF_SIZE) {
        clt_settings.snaplen = PCAP_RCV_BUF_SIZE;
    }

    if (clt_settings.raw_dmac != NULL) {
        tc_log_info(LOG_NOTICE, 0, "target mac:%s", clt_settings.raw_dmac);
        convert_str_to_mac(clt_settings.dmac, clt_settings.raw_dmac);
    } else {
        tc_log_info(LOG_ERR, 0, "no -t argument");
        fprintf(stderr, "no -t argument\n");
        return -1;
    }

    if (clt_settings.raw_smac != NULL) {
        tc_log_info(LOG_NOTICE, 0, "output mac:%s", clt_settings.raw_smac);
        convert_str_to_mac(clt_settings.smac, clt_settings.raw_smac);
    } else {
        tc_log_info(LOG_ERR, 0, "no -s argument");
        fprintf(stderr, "no -s argument\n");
        return -1;
    }


    if (clt_settings.user_filter != NULL) {
        tc_log_info(LOG_NOTICE, 0, "user filter:%s", clt_settings.user_filter);
        len = strlen(clt_settings.user_filter);
        if (len >= MAX_FILTER_LENGH) {
            tc_log_info(LOG_ERR, 0, "user filter is too long");
            return -1;
        }
        memcpy(clt_settings.filter, clt_settings.user_filter, len);

    } else {
        tc_log_info(LOG_ERR, 0, "user filter is null");
        fprintf(stderr, "please set filter first\n");
        return -1;
    }

    if (clt_settings.do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            tc_log_info(LOG_ERR, errno, "Failed to ignore SIGHUP");
        }
        if (daemonize() == -1) {
            fprintf(stderr, "failed to daemonize() in order to daemonize\n");
            return -1;
        }    
    }    

    return 0;
}

static void
settings_init()
{
    /* init values */
    clt_settings.mtu = DEFAULT_MTU;
    clt_settings.mss = DEFAULT_MSS;
    clt_settings.snaplen = PCAP_RCV_BUF_SIZE;
    clt_settings.buffer_size = TC_PCAP_BUF_SIZE;
    clt_settings.output_if_name = NULL;
}


/*
 * main entry point
 */
int
main(int argc, char **argv)
{
    int ret, is_continue = 1;

    settings_init();

    signal(SIGINT,  mirror_over);
    signal(SIGPIPE, mirror_over);
    signal(SIGHUP,  mirror_over);
    signal(SIGTERM, mirror_over);

    tc_time_init();

    if (read_args(argc, argv) == -1) {
        return -1;
    }
    
    if (tc_log_init(clt_settings.log_path) == -1) {
        return -1;
    }

    clt_settings.pool = tc_create_pool(TC_DEFAULT_POOL_SIZE, 0);

    if (clt_settings.pool == NULL) {
        return -1;
    }

    /* output debug info */
    output_for_debug();

    /* set details for running */
    if (set_details() == -1) {
        return -1;
    }

    tc_event_timer_init();

    ret = tc_event_loop_init(&event_loop, MAX_FD_NUM);
    if (ret == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "event loop init failed");
        is_continue = 0;
    } 

    if (is_continue) {
        ret = mirror_init(&event_loop);
        if (ret == TC_ERR) {
            is_continue = 0;
        }   
    }

    if (is_continue) {
        /* run now */
        tc_event_proc_cycle(&event_loop);
    }

    mirror_release_resources();

    return 0;
}


