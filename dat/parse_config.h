/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_PARSE_CONFIG_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_PARSE_CONFIG_H_

#include "wifi/radio.h"

#include <libomcommon/debug_msg.h>
#include <libomcommon/str_util.h>

#include <libubox/blobmsg.h>
#include <libubox/vlist.h>
#include <libubus.h>
#include <netinet/in.h>

#define TB_INT(x, y)														\
do {																		\
	if (parsed_data[x])														\
		y = blobmsg_get_u32(parsed_data[x]);								\
} while (0)

#define TB_BOOL(x, y)														\
do {																		\
	if (parsed_data[x])														\
		y = blobmsg_get_bool(parsed_data[x]);								\
} while (0)

#define TB_STRING(x, y)														\
do {																		\
	if (parsed_data[x])														\
		snprintf(y, sizeof(y), "%s", blobmsg_get_string(parsed_data[x]));	\
} while (0)

#define CP_ADDN_HOSTS_FILE_FMT	"/tmp/cp-hosts%d"

#define DNS_INTERCEPT_BTL_BASE_PORT_NO	(1100)

#define MAX_VLAN_TAG 4095
#define MIN_VLAN_TAG 1
#define VALID_VLAN_TAG(tag) (CHECK_RANGE((tag), MIN_VLAN_TAG, MAX_VLAN_TAG))

#define ACL_MAX					256
#define BATMAN_PROTO_NAME_MAX	12

/* This channel list needs to include more than just DFS channels, so just make it way larger than
 * we'll ever need
 */
#define DFS_MAX_CHANNEL			64

#define DNS_MAX					4
#define KEY_MAX					128
#define RADIO_MAX				3
#define SERVER_MAX				128
#define SSID_MAX				4
#define WIRED_MAX				2

enum wifi_phy_rate_mode {
	PHY_RATE_ENABLE_ALL = 0,
	PHY_RATE_DISABLE_ALL_LOWER_RATES,
	PHY_RATE_DISABLE_11B_RATES,
	PHY_RATE_DISABLE_CUSTOM_RATES,
	__PHY_RATE_ENUM_MAX
};

struct dfs {
	bool enable;
	int channel[DFS_MAX_CHANNEL];
	unsigned int channel_count;
};

struct batman {
	int hop_penalty;
	int gw_stickiness;
	bool bridge_loop_avoidance;
};

struct mesh {
	char protocol[BATMAN_PROTO_NAME_MAX];
	struct batman batman;
	char key[KEY_MAX];
};

struct dhcp {
	bool enable;
	char gateway[INET_ADDRSTRLEN];
	char netmask[INET_ADDRSTRLEN];
	char relay[INET_ADDRSTRLEN];
	int start;
	int num_leases;
	char lease_len[INET_ADDRSTRLEN];
};

struct band {
	int enable;
	char ssid[33];
	bool start_disabled;
};

struct acl_list_entry {
	struct vlist_node vlist_node;
	char mac[MAC_STR_LENGTH + 1];
	int ssid_idx;
};

struct ssid {
	bool parsed;
	bool enable;
	char ssid[33];
	char key[KEY_MAX];
	char enc[32];
	char radius_server[SERVER_MAX];
	char radius_key[KEY_MAX];
	int radius_port;
	int vlan_tag;
	bool bridge_to_lan;
	bool rebind_protection;
	char roaming_domain[5]; /* 80211r roaming domain is 4 characters of hex number */
	char roaming_key[65]; /* 80211r roaming key is either 32 or 64 hex characters */
	char radius_acct_server[SERVER_MAX];
	char radius_acct_key[KEY_MAX];
	int radius_acct_port;
	bool hidden;
	bool neigh_report;
	bool anyip;	/* TODO: We should just get rid of this? */
	bool lan_block;
	bool client_isolate;
	char smtp_redir[SERVER_MAX];
	char dns_server[DNS_MAX][SERVER_MAX];
	bool dns_intercept;
	bool dns_cache_enable;
	char acl[ACL_MAX][18];
	struct vlist_tree *acl_vlist;
	struct band band[BAND_MAX];
	struct dhcp dhcp;

	/* These two settings are used to enable/disable ap_mgr(usteer) features. */
	bool band_steering;
	bool roaming_80211v;

	bool shaping_enable;
	bool wifi_scheduling;

	bool dynamic_vlan;

	int dtim_interval;
};

struct radio {
	int enable;
	int channel;
	char mode[16];
	int txpower;
	int rtscts;
	int disable_lower_rates;
	int minimum_data_rate;

	/* Value to set the wireless UCI mcast_rate option as. This will be derived from the
	 * minimum_data_rate above.
	 */
	int mcast_rate;
	bool mesh_enable;
};

/* NOTE: wifi scheduling is handled through cloud configuration */
struct wifi_settings {
	bool enable;
	bool ap_scan;
	bool delayed_wifi;
	bool save_orphans;
	bool roaming_vlans; /* TODO: Need to handle this */
	bool disable_wired_client;

	bool reg_outdoor; /* TODO: Need to handle this */
	char reg_country[3];

	struct dfs dfs;
	struct ssid ssid[SSID_MAX];
	struct radio radio[RADIO_MAX];
	struct mesh mesh;

	int wired_client_ssid;

	char radio_override[128];
	char override_reason[32];

	int node_id;

	char orphan_connect_bssid[32];
	int orphan_connect_radio;

	int scanning_period;
	int scanning_phy;

	int survey_phy;
	int survey_period;
	int survey_dwell_time;

	bool presence_enable;
	int presence_period;

	int antenna_type;

	int recover_config_errors;

	bool dpi_enable;
};

extern struct wifi_settings gWifi_settings;

void wifi_restore_config_enabled_interfaces(bool reload);
uint16_t get_ip_id(int node_id);
void wifi_set_radio_override(const char *override_reason, struct wifi_settings *settings);
int wifi_parse_config(bool enable, struct blob_attr *msg);
void wifid_parse_config_event_handler(struct ubus_context *uctx, struct ubus_event_handler *ev, const char *type, struct blob_attr *msg);

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_PARSE_CONFIG_H_ */
