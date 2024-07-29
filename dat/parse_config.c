/***
 *
 * Copyright (C) 2022-2024 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "settings.h"
#include "wifi/bridge.h"
#include "wifi/lldp.h"
#include "wifi/neighbors.h"
#include "wifi/settings/delayed_wifi.h"
#include "wifi/settings/parse_config.h"
#include "wifi/settings/ssid.h"
#include "wifi/settings/uci_addrs.h"
#include "wifi/settings/write_config.h"
#include "wifi/validation.h"

#include <libomcommon/debug_msg.h>
#include <libomcommon/file.h>
#include <libomcommon/str_util.h>
#include <libomcommon/uci.h>

#include <libfwcore/platform/wireless.h>

#include <arpa/inet.h>
#include <inttypes.h>
#include <libubox/avl-cmp.h>
#include <net/if.h>

struct wifi_settings gWifi_settings = {0};

/* Function: wifi_restore_config_enabled_interfaces
 * ************************************************
 * This function will read the 'config_enable' UCI options for each AP and mesh
 * interface and write the value into each interfaces 'enable' option. This will
 * restore the configured interface state to it's previously configured state.
 *
 * Inputs:	void - This function only reads and writes UCI values, no input is needed.
 * Returns:	void
 */
void wifi_restore_config_enabled_interfaces(bool reload)
{
	int ap_iface_enable = 0;
	int mesh_iface_enable = 0;
	int channel = 0;
	char mode[16] = {0};

	if (!wifi_lldp_negotiation_complete()) {
		debug_msg_notice("LLDP negotiation is in progress, skipping wifi interface config restoration");
		return;
	}

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		// Skip scanning radios
		if (platform_wireless_radio_is_scanning(radio_idx))
			continue;

		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
			// Pull in the saved value
			if (ng_uci_data_get_val_int(&ap_iface_enable, uci_addr_ap_config_enable, radio_idx, ssid_idx + 1)) {
				debug_msg_warn("Unable to read 'config_enable' UCI option for iface ap%i_%i", radio_idx, ssid_idx + 1);
			} else {
				// Save that value back to the wireless section
				ng_uci_tmp_val_int(ap_iface_enable, uci_addr_ap_enable, radio_idx, ssid_idx + 1);
			}
		}

		// Pull in the saved value
		if (ng_uci_data_get_val_int(&mesh_iface_enable, uci_addr_mesh_config_enable, radio_idx)) {
			debug_msg_warn("Unable to read 'config_enable' UCI option for iface mesh%i", radio_idx);
		} else if (ng_uci_data_get_val_int(&channel, uci_addr_radio_channel, radio_idx)) {
			debug_msg_warn("Unable to read 'channel' UCI option for radio%i", radio_idx);
			// Save that value back to the wireless section
			ng_uci_tmp_val_int(mesh_iface_enable, uci_addr_mesh_enable, radio_idx);
		} else if (ng_uci_data_get_val(mode, sizeof(mode), uci_addr_radio_htmode, radio_idx)) {
			debug_msg_warn("Unable to read 'htmode' UCI option for radio%i", radio_idx);
			// Save that value back to the wireless section
			ng_uci_tmp_val_int(mesh_iface_enable, uci_addr_mesh_enable, radio_idx);
		} else {
			debug_msg_debug("Set uci_addr_mesh_enable to %d, mesh_iface_enable: %d channel_is_dfs: %d", (wifid_channel_is_dfs(channel, mode) ? 0 : mesh_iface_enable), mesh_iface_enable, wifid_channel_is_dfs(channel, mode));
			ng_uci_tmp_val_int((wifid_channel_is_dfs(channel, mode) ? 0 : mesh_iface_enable), uci_addr_mesh_enable, radio_idx);					// Save that value back to the wireless section
		}

		// Disable orph_connX ifaces if we aren't in an override state
		if (!gWifi_settings.radio_override[0])
			ng_uci_tmp_val_int(0, uci_addr_orph_conn_enable, radio_idx);
	}

	// TODO: Make cloud_comm the sole controller of reloading the system config
	ng_uci_commit("wireless");

	if (reload)
		system("reload_config");
}

uint16_t get_ip_id(int node_id)
{
	uint16_t ip_id = 0;

	if (node_id >= 0) {
		/* Use node id for setting IP addrs */
		ip_id = (uint16_t) node_id;
		ip_id = (1 << 16) - (ip_id * 4 * (SSID_MAX + 1));
	} else {
		/* No valid node_id, use MAC address */
		char *mgmt_mac = platform_get_management_mac();

		if (!mgmt_mac) {
			ip_id = (253 << 8);
		} else {
			unsigned char mac_bin[MAC_LENGTH] = {0};

			if (sscanf(mgmt_mac, MAC_FMT_SCAN, MAC_ARG_SCAN(mac_bin)) < 6) {
				ip_id = (253 << 8);
			} else {
				ip_id = ((uint16_t) mac_bin[4]) << 10;
				ip_id |= ((uint16_t) mac_bin[5]) << 2;
			}
		}
	}

	return ip_id;
}

enum {
	RADIO_ENABLE,
	RADIO_BAND,
	RADIO_CHANNEL,
	RADIO_MODE,
	RADIO_TXPOWER,
	RADIO_RTSCTS,
	RADIO_DISABLE_LOWER_RATES,
	RADIO_MINIMUM_DATA_RATE,
	RADIO_MESH_ENABLE,
	__RADIO_MAX,
};

static const struct blobmsg_policy radio_policy[] = {
	[RADIO_ENABLE] = { "enable", BLOBMSG_TYPE_BOOL },
	[RADIO_BAND] = { "band", BLOBMSG_TYPE_STRING },
	[RADIO_CHANNEL] = { "channel", BLOBMSG_TYPE_INT32 },
	[RADIO_MODE] = { "mode", BLOBMSG_TYPE_STRING },
	[RADIO_TXPOWER] = { "txpower", BLOBMSG_TYPE_INT32 },
	[RADIO_RTSCTS] = { "rtscts", BLOBMSG_TYPE_INT32 },
	[RADIO_DISABLE_LOWER_RATES] = { "disable_lower_rates", BLOBMSG_TYPE_INT32 },
	[RADIO_MINIMUM_DATA_RATE] = { "minimum_data_rate", BLOBMSG_TYPE_INT32 },
	[RADIO_MESH_ENABLE] = { "mesh_enable", BLOBMSG_TYPE_BOOL },
};

// All params must be verified by calling function
static int wifid_parse_radio(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__RADIO_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(radio_policy, __RADIO_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!parsed_data[RADIO_BAND]) {
		debug_msg_err("Failed to find 'band' key in msg");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	char band[16] = {0};

	TB_STRING(RADIO_BAND, band);

	if (wifid_find_band_by_type(band) == BAND_SCANNING) {
		// TODO: Handle any configuration for the scanning radio
		debug_msg_debug("Skipping scanning radio");
		return UBUS_STATUS_OK;
	}

	int idx = platform_wireless_get_radio_idx(band);
	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	if (!IS_VALID_ARRAY_INDEX(idx, ap_radio_max)) {
		debug_msg_err("invalid radio index: %d", idx);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	TB_BOOL(RADIO_ENABLE, parsed_settings->radio[idx].enable);
	TB_INT(RADIO_CHANNEL, parsed_settings->radio[idx].channel);

	if (!sys_is_valid_channel_5GHz(parsed_settings->radio[idx].channel) && !sys_is_valid_channel_2_4GHz(parsed_settings->radio[idx].channel)) {
		debug_msg_err("invalid channel: %d", parsed_settings->radio[idx].channel);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	TB_STRING(RADIO_MODE, parsed_settings->radio[idx].mode);
	TB_INT(RADIO_TXPOWER, parsed_settings->radio[idx].txpower);
	TB_INT(RADIO_RTSCTS, parsed_settings->radio[idx].rtscts);
	TB_INT(RADIO_DISABLE_LOWER_RATES, parsed_settings->radio[idx].disable_lower_rates);
	TB_INT(RADIO_MINIMUM_DATA_RATE, parsed_settings->radio[idx].minimum_data_rate);
	TB_BOOL(RADIO_MESH_ENABLE, parsed_settings->radio[idx].mesh_enable);

	return UBUS_STATUS_OK;
}

enum {
	DFS_ENABLE,
	DFS_CHANLIST,
	__DFS_MAX,
};

static const struct blobmsg_policy dfs_policy[] = {
	[DFS_ENABLE] = { "enable", BLOBMSG_TYPE_BOOL },
	[DFS_CHANLIST] = { "channels", BLOBMSG_TYPE_ARRAY },
};

// All params must be verified by calling function
static int wifid_parse_dfs(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__DFS_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(dfs_policy, __DFS_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	TB_BOOL(DFS_ENABLE, parsed_settings->dfs.enable);

	if (parsed_data[DFS_CHANLIST]) {
		/* We have a new list, clear out the old one */
		memset(parsed_settings->dfs.channel, 0, sizeof(parsed_settings->dfs.channel));
		parsed_settings->dfs.channel_count = 0;

		struct blob_attr *cur;
		int rem;

		blobmsg_for_each_attr(cur, parsed_data[DFS_CHANLIST], rem) {
			if (blobmsg_type(cur) != BLOBMSG_TYPE_INT32)
				continue;

			parsed_settings->dfs.channel[parsed_settings->dfs.channel_count] = blobmsg_get_u32(cur);

			if (++parsed_settings->dfs.channel_count >= DFS_MAX_CHANNEL)
				break;
		}
	}

	return UBUS_STATUS_OK;
}

enum {
	REG_OUTDOOR,
	REG_COUNTRY,
	REG_DFS,
	__REG_MAX
};

static const struct blobmsg_policy reg_policy[] = {
	[REG_OUTDOOR] = { "outdoor", BLOBMSG_TYPE_BOOL },
	[REG_COUNTRY] = { "country", BLOBMSG_TYPE_STRING },
	[REG_DFS] = { "dfs", BLOBMSG_TYPE_TABLE },
};

// All params must be verified by calling function
static int wifid_parse_reg(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__REG_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(reg_policy, __REG_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	TB_BOOL(REG_OUTDOOR, parsed_settings->reg_outdoor);

	if (parsed_data[REG_COUNTRY]) {
		char *country = blobmsg_get_string(parsed_data[REG_COUNTRY]);

		if (strlen(country) != 2) {
			debug_msg_err("Got incorrect length for country '%s'", NC(country));
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		snprintf(parsed_settings->reg_country, sizeof(parsed_settings->reg_country), "%s", country);
	}

	if (parsed_data[REG_DFS] && wifid_parse_dfs(parsed_settings, parsed_data[REG_DFS])) {
		debug_msg_err("Failed to parse DFS");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return UBUS_STATUS_OK;
}

enum {
	BATMAN_HOP_PENALTY,
	BATMAN_GW_STICKINESS,
	BATMAN_BRIDGE_LOOP_AVOIDANCE,
	__BATMAN_MAX,
};

static const struct blobmsg_policy batman_policy[] = {
	[BATMAN_HOP_PENALTY] = { "hop_penalty", BLOBMSG_TYPE_INT32 },
	[BATMAN_GW_STICKINESS] = { "gw_stickiness", BLOBMSG_TYPE_INT32 },
	[BATMAN_BRIDGE_LOOP_AVOIDANCE] = { "bridge_loop_avoidance", BLOBMSG_TYPE_BOOL },
};

static int wifid_parse_batman(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__BATMAN_MAX];

	if (blobmsg_parse(batman_policy, __BATMAN_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse batman arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	// pull out the batman settings
	TB_INT(BATMAN_HOP_PENALTY, parsed_settings->mesh.batman.hop_penalty);
	TB_INT(BATMAN_GW_STICKINESS, parsed_settings->mesh.batman.gw_stickiness);
	TB_BOOL(BATMAN_BRIDGE_LOOP_AVOIDANCE, parsed_settings->mesh.batman.bridge_loop_avoidance);

	return UBUS_STATUS_OK;
}

enum {
	MESH_PROTOCOL,
	MESH_BATMAN,
	MESH_KEY,
	__MESH_MAX,
};

static const struct blobmsg_policy mesh_policy[] = {
	[MESH_PROTOCOL] = { "protocol", BLOBMSG_TYPE_STRING },
	[MESH_BATMAN] = { "batman", BLOBMSG_TYPE_TABLE },
	[MESH_KEY] = { "key", BLOBMSG_TYPE_STRING },
};

// All params must be verified by calling function
static int wifid_parse_mesh(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__MESH_MAX];

	debug_blobmsg_dump(msg);

	if (blobmsg_parse(mesh_policy, __MESH_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse mesh arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	// pull out the mesh protocol and key
	TB_STRING(MESH_PROTOCOL, parsed_settings->mesh.protocol);
	TB_STRING(MESH_KEY, parsed_settings->mesh.key);

	if (parsed_data[MESH_BATMAN] && (wifid_parse_batman(parsed_settings, parsed_data[MESH_BATMAN]) != UBUS_STATUS_OK)) {
		debug_msg_err("Unable to parse batman settings");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return UBUS_STATUS_OK;
}

enum {
	ORPHAN_CONNECT_RADIO,
	ORPHAN_CONNECT_BSSID,
	__ORPHAN_CONNECT_MAX
};

static const struct blobmsg_policy orphan_connect_policy[] = {
	[ORPHAN_CONNECT_RADIO] = { "radio", BLOBMSG_TYPE_STRING },
	[ORPHAN_CONNECT_BSSID] = { "bssid", BLOBMSG_TYPE_STRING },
};

// All params must be verified by calling function
static int wifid_parse_orphan_connect(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__ORPHAN_CONNECT_MAX];

	debug_blobmsg_dump(msg);

	if (blobmsg_parse(orphan_connect_policy, __ORPHAN_CONNECT_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse orphan_connect arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!parsed_data[ORPHAN_CONNECT_RADIO]) {
		debug_msg_err("No radio for orphan_connect");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	parsed_settings->orphan_connect_radio = platform_wireless_get_radio_idx(blobmsg_get_string(parsed_data[ORPHAN_CONNECT_RADIO]));

	if (parsed_settings->orphan_connect_radio < 0) {
		debug_msg_err("Invalid radio for orphan_connect");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!parsed_data[ORPHAN_CONNECT_BSSID]) {
		debug_msg_err("No bssid for orphan_connect");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	snprintf(parsed_settings->orphan_connect_bssid, sizeof(parsed_settings->orphan_connect_bssid), "%s", blobmsg_get_string(parsed_data[ORPHAN_CONNECT_BSSID]));

	return UBUS_STATUS_OK;
}

void wifi_set_radio_override(const char *override_reason, struct wifi_settings *settings)
{
	NULL_ASSERT2(VOID_RETURN_VALUE, override_reason, settings);

	if (gWifi_settings.radio_override[0])
		debug_msg_notice("Radio override already in place, setting up new override");

	struct timespec tp = {0};

	clock_gettime(CLOCK_MONOTONIC_RAW, &tp);

	snprintf(settings->radio_override, sizeof(settings->radio_override), "%" PRId64 ".%ld", tp.tv_sec, tp.tv_nsec);
	snprintf(settings->override_reason, sizeof(settings->override_reason), "%s", override_reason);

	debug_msg_notice("Got override %s at time %s", settings->override_reason, settings->radio_override);

	ng_uci_set_string(gDatto_net_state.uci_ctx, settings->radio_override, "%s", uci_addr_radio_override);
	ng_uci_set_string(gDatto_net_state.uci_ctx, settings->override_reason, "%s", uci_addr_override_reason);
}

enum {
	WIFI_ENABLE,
	WIFI_AP_SCAN,
	WIFI_MESH,
	WIFI_REGULATORY,
	WIFI_RADIOS,
	WIFI_SSIDS,
	WIFI_DELAYED_WIFI,
	WIFI_NEIGHBORS,
	WIFI_NODE_ID,
	WIFI_LONELY_FRIEND,
	WIFI_CHANNEL_CHANGE_NONCE,
	WIFI_SAVE_ORPHANS,
	WIFI_ORPHAN_CONNECT,
	WIFI_SCANNING_PERIOD,
	WIFI_SURVEY_PERIOD,
	WIFI_SURVEY_DWELL_TIME,
	WIFI_PRESENCE_ENABLE,
	WIFI_PRESENCE_PERIOD,
	WIFI_ANTENNA_TYPE,
	__WIFI_MAX,
};

static const struct blobmsg_policy wifi_policy[] = {
	[WIFI_ENABLE] = { "enable", BLOBMSG_TYPE_BOOL },
	[WIFI_AP_SCAN] = { "ap_scan", BLOBMSG_TYPE_BOOL },
	[WIFI_MESH] = { "mesh", BLOBMSG_TYPE_TABLE },
	[WIFI_REGULATORY] = { "regulatory", BLOBMSG_TYPE_TABLE },
	[WIFI_RADIOS] = { "radios", BLOBMSG_TYPE_ARRAY },
	[WIFI_SSIDS] = { "ssids", BLOBMSG_TYPE_ARRAY },
	// NOT changed to delayed_wifi_settings to prevent changes to the device<->cloud communication
	[WIFI_DELAYED_WIFI] = {"delayed_settings", BLOBMSG_TYPE_BOOL },
	[WIFI_NEIGHBORS] = { "neighbors", BLOBMSG_TYPE_ARRAY },
	[WIFI_NODE_ID] = { .name = "node_id", .type = BLOBMSG_TYPE_INT32 },
	[WIFI_LONELY_FRIEND] = { .name = "lonely_friend", .type = BLOBMSG_TYPE_BOOL },
	[WIFI_CHANNEL_CHANGE_NONCE] = { .name = "channel_change_nonce", .type = BLOBMSG_TYPE_STRING },
	[WIFI_SAVE_ORPHANS] = { "save_orphans", BLOBMSG_TYPE_ARRAY },
	[WIFI_ORPHAN_CONNECT] = { "orphan_connect", BLOBMSG_TYPE_TABLE },
	[WIFI_SCANNING_PERIOD] = { .name = "scanning_period", .type = BLOBMSG_TYPE_INT32 },
	[WIFI_SURVEY_PERIOD] = { .name = "survey_period", .type = BLOBMSG_TYPE_INT32 },
	[WIFI_SURVEY_DWELL_TIME] = { .name = "survey_dwell_time", .type = BLOBMSG_TYPE_INT32 },
	[WIFI_PRESENCE_ENABLE] = { .name = "presence_enable", .type = BLOBMSG_TYPE_BOOL },
	[WIFI_PRESENCE_PERIOD] = { .name = "presence_period", .type = BLOBMSG_TYPE_INT32 },
	[WIFI_ANTENNA_TYPE] = { .name = "antenna_type", .type = BLOBMSG_TYPE_STRING },
};

static void parse_config_acl_update(struct vlist_tree OM_UNUSED(*tree), struct vlist_node OM_UNUSED(*running_acl_node), struct vlist_node *parsed_acl_node)
{
	/*
	 * This implementation of a vlist update callback is a bit backwards, please do not
	 * use it for reference.
	 *
	 * We still need to be able to free a node if it was deleted, but otherwise don't do
	 * anything here.  While we're adding parsed ACL entries, or when we're cleaning up
	 * the memory for this list, we're just level setting the baseline.  We will change
	 * the "update" callback when we get into "write_config", and use the update callback
	 * in there to write out the UCI entries.
	 *
	 * Due to the way vlists work, any node provided in the "parsed_acl_node" param has
	 * been removed from the vlist, so we need to free its memory.
	 */
	if (parsed_acl_node) {
		struct acl_list_entry *parsed_acl_entry = container_of(parsed_acl_node, struct acl_list_entry, vlist_node);

		free(parsed_acl_entry); /* NOT explicitly set to NULL on next line, immediate return */
		return;
	}
}

static int wifid_parse_config(struct blob_attr *msg)
{
	NULL_ASSERT(UBUS_STATUS_INVALID_ARGUMENT, msg);
	struct wifi_settings parsed_settings; /* immediately copied from global */
	int ret = UBUS_STATUS_OK;

	memcpy(&parsed_settings, &gWifi_settings, sizeof(parsed_settings));

	/*
	 * Don't populate these lists with the running configuration.  We need to add all of
	 * the acl entries from the parsed config first, then in write_config add the ones
	 * from the currently running lists.  This is done so that we aren't getting update
	 * callbacks telling us to write UCI changes until we're in write_config and ready
	 * for them to happen.
	 *
	 * This is unusual for vlist implementations, and should not be used as a reference
	 * implementation.
	 */
	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		parsed_settings.ssid[ssid_idx].acl_vlist = calloc(1, sizeof(struct vlist_tree));
		if (!parsed_settings.ssid[ssid_idx].acl_vlist) {
			debug_msg_err("Unable to allocate memory for ACL vlists");
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		vlist_init(parsed_settings.ssid[ssid_idx].acl_vlist, avl_strcmp, parse_config_acl_update);
	}

	struct blob_attr *parsed_data[__WIFI_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(wifi_policy, __WIFI_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	TB_BOOL(WIFI_ENABLE, parsed_settings.enable);
	TB_BOOL(WIFI_DELAYED_WIFI, parsed_settings.delayed_wifi);

	/*
	 * This flag is currently controlling whether we allow hostapd to automatically change the
	 * primary channel depending on a scan for other BSSes on this same channel.  It has nothing
	 * to do with the AutoRF/Neighbor list scanning, which is what this option was originally
	 * intended for.  This option from the cloud is likely no longer needed, and we'll probably
	 * set this "ap_scan"/uci option "noscan" to 0 when we have better OBSS support so that
	 * we can let the AP make intelligent decisions about what primary channel to occupy.
	 */
	parsed_settings.ap_scan = 0;

	TB_INT(WIFI_NODE_ID, parsed_settings.node_id);

	if (parsed_data[WIFI_MESH] && wifid_parse_mesh(&parsed_settings, parsed_data[WIFI_MESH])) {
		debug_msg_err("Failed to parse mesh data");
		ret =  UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	if (parsed_data[WIFI_REGULATORY] && wifid_parse_reg(&parsed_settings, parsed_data[WIFI_REGULATORY])) {
		debug_msg_err("Failed to parse regulatory data");
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	if (parsed_data[WIFI_RADIOS]) {
		struct blob_attr *cur;
		int rem;

		blobmsg_for_each_attr(cur, parsed_data[WIFI_RADIOS], rem) {
			if (wifid_parse_radio(&parsed_settings, cur)) {
				debug_msg_err("Failed to parse radios data");
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}
		}
	}

	if (parsed_data[WIFI_SSIDS]) {
		struct blob_attr *cur;
		int rem;

		blobmsg_for_each_attr(cur, parsed_data[WIFI_SSIDS], rem) {
			if (wifid_parse_ssid(&parsed_settings, cur)) {
				debug_msg_err("Failed to parse ssids data");
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}
		}
	}

	if (parsed_data[WIFI_NEIGHBORS] && wifid_parse_neighbor_list(parsed_data[WIFI_NEIGHBORS])) {
		debug_msg_err("Failed to parse neighbor list");
		ret = UBUS_STATUS_INVALID_ARGUMENT;
		goto out;
	}

	if (parsed_data[WIFI_CHANNEL_CHANGE_NONCE]) {
		if (!strcmp(parsed_settings.radio_override, blobmsg_get_string(parsed_data[WIFI_CHANNEL_CHANGE_NONCE]))) {
			debug_msg_notice("Cloud has acknowledged our channel change, obeying configs again");
			parsed_settings.radio_override[0] = '\0';
			parsed_settings.override_reason[0] = '\0';
			parsed_settings.orphan_connect_radio = 0;
			parsed_settings.orphan_connect_bssid[0] = '\0';
		}
	}

	if (parsed_data[WIFI_SCANNING_PERIOD])
		parsed_settings.scanning_period = blobmsg_get_u32(parsed_data[WIFI_SCANNING_PERIOD]) * 60;

	if (parsed_data[WIFI_SURVEY_PERIOD])
		parsed_settings.survey_period = blobmsg_get_u32(parsed_data[WIFI_SURVEY_PERIOD]) * 60;

	if (parsed_data[WIFI_SURVEY_DWELL_TIME])
		parsed_settings.survey_dwell_time = blobmsg_get_u32(parsed_data[WIFI_SURVEY_DWELL_TIME]);

	/* TODO: save off the MAC addresses from this list and use them
	 * to limit who can connect to this SSID
	 */
	parsed_settings.save_orphans = !!parsed_data[WIFI_SAVE_ORPHANS];

	if (parsed_data[WIFI_LONELY_FRIEND]) {
		if (blobmsg_get_bool(parsed_data[WIFI_LONELY_FRIEND])) {
			wifi_set_radio_override("lonely", &parsed_settings);

			/* Assume we've parsed the SSIDs, so that we write out the configured "enable" flag to
			 * the actual enable flag
			 */
			for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx)
				parsed_settings.ssid[ssid_idx].parsed = true;
		}
	} else if (parsed_data[WIFI_ORPHAN_CONNECT]) {
		ret = wifid_parse_orphan_connect(&parsed_settings, parsed_data[WIFI_ORPHAN_CONNECT]);

		if (ret != UBUS_STATUS_OK)
			goto out;

		wifi_set_radio_override("orphan_connect", &parsed_settings);

		/* Assume we've parsed the SSIDs, so that we write out the configured "enable" flag to the
		 * actual enable flag
		 */
		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx)
			parsed_settings.ssid[ssid_idx].parsed = true;
	} else {
		/* TODO: This check will likely need to be made elsewhere once we have more sources
		 * of local overrides for radio settings
		 */
		if (parsed_settings.radio_override[0]) {
			debug_msg_err("Local radio settings override, ignoring configuration");
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}

	TB_BOOL(WIFI_PRESENCE_ENABLE, parsed_settings.presence_enable);
	TB_INT(WIFI_PRESENCE_PERIOD, parsed_settings.presence_period);

	if (parsed_data[WIFI_ANTENNA_TYPE]) {
		for (int ant_type = 1; ant_type < __ANTENNA_MAX; ++ant_type) {
			if (!strcmp(gAntennas[ant_type], blobmsg_get_string(parsed_data[WIFI_ANTENNA_TYPE]))) {
				parsed_settings.antenna_type = ant_type;
				break;
			}
		}
	}

	if (wifid_write_config(&parsed_settings)) {
		debug_msg_err("Failed to write UCI batch config");
		ret = UBUS_STATUS_INVALID_ARGUMENT;
	}

out:
	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		if (parsed_settings.ssid[ssid_idx].acl_vlist) {
			/* Change the callback to one which just frees deleted nodes.
			 * If we don't do this, then we'll clear the whole ACL from UCI
			 */
			parsed_settings.ssid[ssid_idx].acl_vlist->update = parse_config_acl_update;
			vlist_flush_all(parsed_settings.ssid[ssid_idx].acl_vlist);
			free(parsed_settings.ssid[ssid_idx].acl_vlist); /* Explicitly set to NULL on following line */
			parsed_settings.ssid[ssid_idx].acl_vlist = NULL;
		}
	}

	return ret;
}

enum {
	CONFIG_ENABLE,
	CONFIG_PARAMS,
	__CONFIG_MAX,
};

static const struct blobmsg_policy parse_config_policy[] = {
	[CONFIG_ENABLE]	= { "enable", BLOBMSG_TYPE_BOOL },
	[CONFIG_PARAMS]	= { "params", BLOBMSG_TYPE_TABLE },
};

int wifi_parse_config(bool OM_UNUSED(enable), struct blob_attr *msg)
{
	NULL_ASSERT(UBUS_STATUS_INVALID_ARGUMENT, msg);

	struct blob_attr *parsed_data[__CONFIG_MAX]; /* Zeroed out by blobmsg_parse */

	blobmsg_parse(parse_config_policy, __CONFIG_MAX, parsed_data, blob_data(msg), blob_len(msg));

	if (!parsed_data[CONFIG_PARAMS]) {
		debug_msg_err("Failed to find 'params' key in msg");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return wifid_parse_config(parsed_data[CONFIG_PARAMS]);
}

enum parse_config_event_policy {
	PARSE_CONFIG_EVENT_SUCCESS,
	__PARSE_CONFIG_EVENT_MAX
};

const struct blobmsg_policy ubus_parse_config_event_policy[__PARSE_CONFIG_EVENT_MAX] = {
	[PARSE_CONFIG_EVENT_SUCCESS] = { .name = "success", .type = BLOBMSG_TYPE_BOOL},
};

void wifid_parse_config_event_handler(struct ubus_context *uctx, struct ubus_event_handler OM_UNUSED(*ev), const char OM_UNUSED(*type), struct blob_attr *msg)
{
	NULL_ASSERT(VOID_RETURN_VALUE, msg);

	struct blob_attr *parsed_data[__PARSE_CONFIG_EVENT_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(ubus_parse_config_event_policy, __PARSE_CONFIG_EVENT_MAX, parsed_data, blob_data(msg), blob_len(msg))) {
		debug_msg_err("Unable to parse parse_config status event");
		return;
	}

	if (!parsed_data[PARSE_CONFIG_EVENT_SUCCESS]) {
		debug_msg_err("parse_config status event didn't contain success flag");
		return;
	}

	parse_config_event_delayed_wifi(blobmsg_get_bool(parsed_data[PARSE_CONFIG_EVENT_SUCCESS]));
	parse_config_event_neighbors(uctx, blobmsg_get_bool(parsed_data[PARSE_CONFIG_EVENT_SUCCESS]));
}

