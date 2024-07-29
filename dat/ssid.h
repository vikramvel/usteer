/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_SSID_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_SSID_H_

#include "wifi/settings/parse_config.h"

bool wifid_is_ssid_band_enabled(struct wifi_settings *const settings, int ssid_idx, int radio_idx);
int wifid_write_ssid_config(struct wifi_settings *parsed_settings, int ssid_idx);
int wifid_write_ap_iface_config(struct wifi_settings *parsed_settings, int ssid_idx, int radio_idx);
int wifid_parse_ssid(struct wifi_settings *parsed_settings, struct blob_attr *msg);

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_SSID_H_ */
