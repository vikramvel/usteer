/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_RELOAD_CONFIG_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_RELOAD_CONFIG_H_

#include <libomcommon/jobs.h>
#include <libubox/blobmsg.h>
#include <libubox/list.h>
#include <libubox/uloop.h>
#include <libubus.h>
#include <linux/nl80211.h>

#define CTL_VARIANT_FILE				"/etc/modules.d/00-datto_ctl"

/* This channel list needs to include more than just DFS channels, so just make it way larger than
 * we'll ever need
 */
#define DFS_MAX_CHANNEL					64
#define SURVEY_DWELL_TIME_DEFAULT       20                 /* 20 seconds */

struct wifi_scan_state {
	struct list_head scan_results;

	struct ubus_subscriber subscriber;
	uint32_t obj_id;

	bool checkin_after_scan;

	struct dnet_job scan_job;

	struct uloop_timeout periodic_scanning_watchdog;
};

struct wifi_survey_state {
	/* list of interfaces with results */
	struct list_head list_of_survey_result_ifaces;

	struct ubus_subscriber subscriber;
	uint32_t obj_id;

	struct uloop_timeout survey_period;
};

struct mesh_state {
	char *gateway_mac;
	unsigned char gateway_next_hop_mesh_peer_mac_addr[6];
	char *gateway_quality;
	char *gateway_interface;
	char *gateway_route;
	char *gateway_latency;
	char *gateway_rx_bitrate;
	char *gateway_tx_bitrate;
};

struct dfs_chan_state {
	int freq;
	enum nl80211_dfs_state state;
};

struct wifi_lldp_listener {
	struct ubus_subscriber subscriber;
	uint32_t obj_id;
};

struct wifi_state {
	char delayed_wifi_file[128];
	char new_delayed_wifi_file[128];
	struct uloop_timeout delayed_wifi_timer;

	struct list_head *neighbors;
	struct list_head *new_neighbors;
	struct uloop_timeout neighbor_timer;
	uint32_t ap_mgr_ubus_id;
#ifdef	OM_USTEER_ROAM
	uint32_t usteer_ubus_id;
#endif // OM_USTEER_ROAM

	struct uloop_timeout lonely_timer;
	int lonely_trigger_count;

	struct uloop_timeout orphand_timer;

	/* Scanning state */
	struct wifi_scan_state wifi_scanning_state;

	/* Survey state */
	struct wifi_survey_state wifi_survey_state;

	struct uloop_process mesh_batctl_process;
	int mesh_batctl_process_ret_code;
	struct uloop_timeout mesh_state_timer;
	struct mesh_state mesh;

	/* DFS Event listener */
	struct uloop_fd dfs_listener_fd;
	struct nl_sock *dfs_nl_sock;
	struct nl_cb *dfs_nl_cb;

	bool dfs_event_detected;
	struct dfs_chan_state chan_state[DFS_MAX_CHANNEL];

	/* List of new hostapd instances that need their ft_auth_bridge updated */
	struct list_head hapd_instances;
	struct uloop_timeout update_hapd_instances_timer;

	struct wifi_lldp_listener lldp_listener;
};

extern struct wifi_state gWifi_state;

int wifi_reload_config(bool fresh_start);

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_RELOAD_CONFIG_H_ */
