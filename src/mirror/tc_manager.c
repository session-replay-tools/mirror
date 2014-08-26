
#include <xcopy.h>
#include <mirror.h>

/* check resource usage, such as memory usage and cpu usage */
static void
check_resource_usage(tc_event_timer_t *evt)
{
    int           ret, who;
    struct rusage usage;

    who = RUSAGE_SELF;

    ret = getrusage(who, &usage);
    if (ret == -1) {
        tc_log_info(LOG_ERR, errno, "getrusage");
    }

    /* total amount of user time used */
    tc_log_info(LOG_NOTICE, 0, "user time used:%ld", usage.ru_utime.tv_sec);

    /* total amount of system time used */
    tc_log_info(LOG_NOTICE, 0, "sys  time used:%ld", usage.ru_stime.tv_sec);

    /* maximum resident set size (in kilobytes) */
    /* only valid since Linux 2.6.32 */
    tc_log_info(LOG_NOTICE, 0, "max memory size:%ld", usage.ru_maxrss);
    tc_log_info(LOG_NOTICE, 0, "voluntary ctx switches:%ld", usage.ru_nvcsw);
    tc_log_info(LOG_NOTICE, 0, "involuntary ctx switches:%ld", usage.ru_nivcsw);

    if (usage.ru_maxrss > clt_settings.max_rss) {
        tc_log_info(LOG_WARN, 0, "occupies too much memory, limit:%ld",
                 clt_settings.max_rss);
        /* biggest signal number + 1 */
        tc_over = SIGRTMAX;
    }

    if (evt) {
        tc_event_update_timer(evt, 60000);
    }
}


void
mirror_release_resources(void)
{
    int i;

    tc_log_info(LOG_WARN, 0, "sig %d received", tc_over); 

    check_resource_usage(NULL);

    tc_event_loop_finish(&event_loop);
    tc_log_info(LOG_NOTICE, 0, "tc_event_loop_finish over");

    for (i = 0; i < clt_settings.devices.device_num; i++) {
        if (clt_settings.devices.device[i].pcap != NULL) {
            pcap_close(clt_settings.devices.device[i].pcap);
            clt_settings.devices.device[i].pcap = NULL;
        }
    }

    tc_pcap_over();
    tc_destroy_pool(clt_settings.pool);

    tc_log_end();
}


void
mirror_over(const int sig)
{
    tc_over = sig;
}


int
mirror_init(tc_event_loop_t *ev_lp)
{

    tc_event_add_timer(ev_lp->pool, 60000, NULL, check_resource_usage);

    if (tc_packets_init(ev_lp) == TC_ERR) {
        return TC_ERR;
    }

    return TC_OK;
}

