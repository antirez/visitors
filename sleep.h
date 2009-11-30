/* compatibility for the unix/win32 sleep() function */

#ifndef __VI_SLEEP_H
#define __VI_SLEEP_H

#ifdef WIN32
#include <windows.h>
#define vi_sleep(x) Sleep((x)*1000)
#else
#include <unistd.h>
#define vi_sleep(x) sleep(x)
#endif

#endif /* __VI_SLEEP_H */
