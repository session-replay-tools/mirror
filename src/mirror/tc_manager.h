#ifndef  TC_MANAGER_INCLUDED
#define  TC_MANAGER_INCLUDED

#include <xcopy.h>
#include <mirror.h>

int  mirror_init(tc_event_loop_t *event_loop);
void mirror_over(const int sig);
void mirror_release_resources(void);

#endif   /* ----- #ifndef TC_MANAGER_INCLUDED ----- */

