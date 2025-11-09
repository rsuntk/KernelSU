#ifndef __KSU_H_THRONE_TRACKER
#define __KSU_H_THRONE_TRACKER

#include "ksu.h"

struct uid_data {
	struct list_head list;
	u32 uid;
	char package[KSU_MAX_PACKAGE_NAME];
};

void ksu_throne_tracker_init(void);

void ksu_throne_tracker_exit(void);

void track_throne(void);

#endif
