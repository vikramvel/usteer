/***
 *
 * Copyright (C) 2022 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_DUMP_STATE_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_DUMP_STATE_H_

#include <libubox/blobmsg.h>

int wifi_dump_state(bool secure, struct blob_buf *dump_blobmsg);

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_DUMP_STATE_H_ */
