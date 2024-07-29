/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_DELAYED_WIFI_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_DELAYED_WIFI_H_

#include "wifi/settings/parse_config.h"

#define DELAYED_WIFI_TIME	(7 * 60 * 1000)		/* 7 Minutes */

void wifid_cancel_delayed_wifi(void);
int ubus_wifi_end_delayed_wifi(struct ubus_context *ctx, struct ubus_object *obj, struct ubus_request_data *req, const char *method, struct blob_attr *msg);
void parse_config_event_delayed_wifi(bool success);
int wifid_write_delayed_wifi_config(struct wifi_settings *parsed_settings, char *delayed_wifi_file);

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_DELAYED_WIFI_H_ */
