/***
 *
 * Copyright (C) 2021-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_HOSTAPD_FT_MGMT_H
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_HOSTAPD_FT_MGMT_H

#include "wifi/settings/parse_config.h"
#include "wifi/settings/reload_config.h"

#define HAPD_UBUS_NAME_MAX 14	/* this should cover 'hostapd.apX_Y'+1 */

struct hapd_instance {
	struct list_head list;
	char ubus_path[HAPD_UBUS_NAME_MAX];
	uint32_t ubus_id;
	int ssid_idx;
};

void wifi_flush_hapd_instance_list(struct wifi_state *state);
void wifi_remove_hapd_instance_from_list(char *ubus_path);
void wifi_add_hapd_instance_to_list(char *ubus_path, int ssid_idx);
void wifi_enumerate_hapd_instances_add_to_list(void);
void wifi_update_hapd_ft_auth_bridges(struct wifi_settings *settings);
void wifi_update_hapd_ft_auth_bridges_delayed(struct uloop_timeout *timer);
void wifi_dump_hapd_ft_auth_bridges_state(struct blob_buf *dump_blobmsg);

#endif // __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_HOSTAPD_FT_MGMT_H
