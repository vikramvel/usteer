/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_WRITE_CONFIG_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_WRITE_CONFIG_H_

#include "wifi/settings/parse_config.h"

int wifid_write_config(struct wifi_settings *parsed_settings);
bool __attribute__((const)) wifid_minimum_data_rate_is_valid(int minimum_data_rate);

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_WRITE_CONFIG_H_ */
