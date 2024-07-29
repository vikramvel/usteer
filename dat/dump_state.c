/***
 *
 * Copyright (C) 2019-2024 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "settings.h"
#include "wifi/ap_scan.h"
#include "wifi/ap_survey.h"
#include "wifi/neighbors.h"
#include "wifi/nl80211.h"
#include "wifi/settings/dump_state.h"
#include "wifi/settings/hostapd_ft_mgmt.h"
#include "wifi/settings/parse_config.h"
#include "wifi/settings/reload_config.h"
#include "wired/online.h"

#include <libomcommon/blobmsg.h>
#include <libomcommon/common.h>
#include <libomcommon/debug_msg.h>

#include <libfwcore/platform/wireless.h>

/* Array of strings for all of the wifi_phy_rate_mode enum items.
 * This will be used in dump state to make the 'disable_lower_rates' value more readable.
 */
static const char *wifi_phy_rate_mode_strings[] = {
	[PHY_RATE_ENABLE_ALL] = "enable_all",
	[PHY_RATE_DISABLE_ALL_LOWER_RATES] = "disable_all_lower_rates",
	[PHY_RATE_DISABLE_11B_RATES] = "disable_11b_rates",
	[PHY_RATE_DISABLE_CUSTOM_RATES] = "disable_custom_rates"
};

static void wifi_dump_roam_per_ssid_settings(struct blob_buf *dump_blobmsg, int ssid_idx)
{
	NULL_ASSERT(VOID_RETURN_VALUE, dump_blobmsg);

	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX)) {
		debug_msg_err("Passed SSID index is out of range, passed %d vs max %d", ssid_idx, SSID_MAX);
		return;
	}

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "band_steering", gWifi_settings.ssid[ssid_idx].band_steering, "Unable to add band_steering for ssid %d", ssid_idx + 1);
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "roaming_80211v", gWifi_settings.ssid[ssid_idx].roaming_80211v, "Unable to add 'roaming_80211v' for ssid %d", ssid_idx + 1);
}

static void wifi_dump_ssid_settings(struct blob_buf *dump_blobmsg, bool secure)
{
	NULL_ASSERT(VOID_RETURN_VALUE, dump_blobmsg);

	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		void *ssid_cookie = blobmsg_open_table(dump_blobmsg, "ssid");

		if (!ssid_cookie) {
			debug_msg_warn("Unable to add ssid %d to dump structure", ssid_idx + 1);
			continue;
		}

		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "index", ssid_idx + 1, "Unable to add ssid %d index", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "enable", gWifi_settings.ssid[ssid_idx].enable, "Unable to add ssid %d enable flag", ssid_idx + 1);

		if (!gWifi_settings.ssid[ssid_idx].enable) {
			blobmsg_close_table(dump_blobmsg, ssid_cookie);
			ssid_cookie = NULL;
			continue;
		}

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "name", gWifi_settings.ssid[ssid_idx].ssid, "Unable to add ssid %d name", ssid_idx + 1);

		if (secure)
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "key", gWifi_settings.ssid[ssid_idx].key, "Unable to add ssid %d key", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "enc", gWifi_settings.ssid[ssid_idx].enc, "Unable to add ssid %d enc", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "radius_server", gWifi_settings.ssid[ssid_idx].radius_server, "Unable to add ssid %d radius_server", ssid_idx + 1);

		if (secure)
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "radius_key", gWifi_settings.ssid[ssid_idx].radius_key, "Unable to add ssid %d radius_key", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "radius_port", gWifi_settings.ssid[ssid_idx].radius_port, "Unable to add ssid %d radius_port", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "radius_acct_server", gWifi_settings.ssid[ssid_idx].radius_acct_server, "Unable to add ssid %d radius_acct_server", ssid_idx + 1);

		if (secure)
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "radius_acct_key", gWifi_settings.ssid[ssid_idx].radius_acct_key, "Unable to add ssid %d radius_acct_key", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "radius_acct_port", gWifi_settings.ssid[ssid_idx].radius_acct_port, "Unable to add ssid %d radius_acct_port", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "vlan_tag", gWifi_settings.ssid[ssid_idx].vlan_tag, "Unable to add ssid %d vlan_tag", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "bridge_to_lan", gWifi_settings.ssid[ssid_idx].bridge_to_lan, "Unable to add ssid %d bridge_to_lan flag", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "rebind_protection", gWifi_settings.ssid[ssid_idx].rebind_protection, "Unable to add ssid %d rebind_protection flag", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "roaming_domain", gWifi_settings.ssid[ssid_idx].roaming_domain, "Unable to add ssid %d roaming domain", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "roaming_key", gWifi_settings.ssid[ssid_idx].roaming_key, "Unable to add ssid %d roaming key", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "hidden", gWifi_settings.ssid[ssid_idx].hidden, "Unable to add ssid %d hidden flag", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "neigh_report", gWifi_settings.ssid[ssid_idx].neigh_report, "Unable to add ssid %d neighbor report flag", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "anyip", gWifi_settings.ssid[ssid_idx].anyip, "Unable to add ssid %d anyip flag", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "lan_block", gWifi_settings.ssid[ssid_idx].lan_block, "Unable to add ssid %d lan_block flag", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "client_isolate", gWifi_settings.ssid[ssid_idx].client_isolate, "Unable to add ssid %d client_isolate flag", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "smtp_redir", gWifi_settings.ssid[ssid_idx].smtp_redir, "Unable to add ssid %d smtp_redir domain", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "dns_intercept", gWifi_settings.ssid[ssid_idx].dns_intercept, "Unable to add ssid %d dns_intercept", ssid_idx + 1);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "dns_cache_enable", gWifi_settings.ssid[ssid_idx].dns_cache_enable, "Unable to add ssid %d dns_cache_enable", ssid_idx + 1);

		void *dns_cookie = blobmsg_open_array(dump_blobmsg, "dns_servers");

		if (dns_cookie) {
			for (int dns_idx = 0; dns_idx < DNS_MAX; ++dns_idx) {
				if (!gWifi_settings.ssid[ssid_idx].dns_server[dns_idx][0])
					break;

				BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "dns_server", gWifi_settings.ssid[ssid_idx].dns_server[dns_idx], "Unable to add ssid %d dns_server %d", ssid_idx + 1, dns_idx);
			}

			blobmsg_close_array(dump_blobmsg, dns_cookie);
			dns_cookie = NULL;
		}

		void *acl_cookie = blobmsg_open_array(dump_blobmsg, "acl_list");

		if (acl_cookie) {
			struct acl_list_entry *acl_entry = NULL;

			if (gWifi_settings.ssid[ssid_idx].acl_vlist) {
				vlist_for_each_element(gWifi_settings.ssid[ssid_idx].acl_vlist, acl_entry, vlist_node)
					BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "acl_mac", acl_entry->mac, "Unable to add ssid %d acl_mac '%s'", ssid_idx + 1, acl_entry->mac);
			}

			blobmsg_close_array(dump_blobmsg, acl_cookie);
			acl_cookie = NULL;
		}

		void *band_cookie = blobmsg_open_table(dump_blobmsg, "bands");

		if (band_cookie) {
			for (int band_idx = 0; band_idx < BAND_MAX; ++band_idx) {
				/* Valid bands are not necessarily contiguous, check them all */
				if (!gWifi_settings.ssid[ssid_idx].band[band_idx].ssid[0])
					continue;

				// TODO: We still probably want to dump something for the scanning radio eventually?
				if (band_idx == BAND_SCANNING)
					continue;

				void *band_name_cookie = blobmsg_open_table(dump_blobmsg, gBands[band_idx]);

				if (band_name_cookie) {
					BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "ssid_name", gWifi_settings.ssid[ssid_idx].band[band_idx].ssid, "Unable to add per band SSID name for ssid %d band '%s'", ssid_idx + 1, gBands[band_idx]);
					BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "enable", gWifi_settings.ssid[ssid_idx].band[band_idx].enable, "Unable to add per band enable for ssid %d band '%s'", ssid_idx + 1, gBands[band_idx]);
					BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "start_disabled", gWifi_settings.ssid[ssid_idx].band[band_idx].start_disabled, "Unable to add 'start_disabled' flag for ssid %d band '%s'", ssid_idx + 1, gBands[band_idx]);

					blobmsg_close_table(dump_blobmsg, band_name_cookie);
					band_name_cookie = NULL;
				}
			}

			blobmsg_close_table(dump_blobmsg, band_cookie);
			band_cookie = NULL;
		}

		void *dhcp_cookie = blobmsg_open_table(dump_blobmsg, "dhcp");

		if (dhcp_cookie) {
			BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "enable", gWifi_settings.ssid[ssid_idx].dhcp.enable, "Unable to add per dhcp enable for ssid %d", ssid_idx + 1);
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway", gWifi_settings.ssid[ssid_idx].dhcp.gateway, "Unable to add per dhcp gateway for ssid %d", ssid_idx + 1);
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "netmask", gWifi_settings.ssid[ssid_idx].dhcp.netmask, "Unable to add per dhcp netmask for ssid %d", ssid_idx + 1);
			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "start", gWifi_settings.ssid[ssid_idx].dhcp.start, "Unable to add per dhcp start for ssid %d", ssid_idx + 1);
			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "num_leases", gWifi_settings.ssid[ssid_idx].dhcp.num_leases, "Unable to add per dhcp num_leases for ssid %d", ssid_idx + 1);
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "lease_len", gWifi_settings.ssid[ssid_idx].dhcp.lease_len, "Unable to add per dhcp lease_len for ssid %d", ssid_idx + 1);

			blobmsg_close_table(dump_blobmsg, dhcp_cookie);
			dhcp_cookie = NULL;
		}

		/* Dump ap_mgr(usteer) per-ssid settings */
		wifi_dump_roam_per_ssid_settings(dump_blobmsg, ssid_idx);

		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "shaping_enable", gWifi_settings.ssid[ssid_idx].shaping_enable, "Unable to add 'shaping_enable' flag for ssid %d", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "wifi_scheduling", gWifi_settings.ssid[ssid_idx].wifi_scheduling, "Unable to add 'wifi_scheduling' flag for ssid %d", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "dynamic_vlan", gWifi_settings.ssid[ssid_idx].dynamic_vlan, "Unable to add 'dynamic_vlan' flag for ssid %d", ssid_idx + 1);

		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "dtim_interval", gWifi_settings.ssid[ssid_idx].dtim_interval, "Unable to add 'dtim_interval' value for ssid %d", ssid_idx + 1);

		blobmsg_close_table(dump_blobmsg, ssid_cookie);
		ssid_cookie = NULL;
	}
}

static void wifi_dump_radio_settings(struct blob_buf *dump_blobmsg)
{
	NULL_ASSERT(VOID_RETURN_VALUE, dump_blobmsg);

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		int band = wifid_find_band(radio_idx);

		if (!IS_VALID_ARRAY_INDEX(band, BAND_MAX))
			continue;

		void *radio_cookie = blobmsg_open_table(dump_blobmsg, "radio");

		if (!radio_cookie) {
			debug_msg_warn("Unable to add radio %d to dump structure", radio_idx);
			continue;
		}
		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "index", radio_idx, "Unable to add radio %d index", radio_idx);
		BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "enable", gWifi_settings.radio[radio_idx].enable, "Unable to add radio %d enable flag", radio_idx);
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "band", gBands[band], "Unable to add radio %d band", radio_idx);

		if (gWifi_settings.radio[radio_idx].enable) {
			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "channel", gWifi_settings.radio[radio_idx].channel, "Unable to add radio %d channel", radio_idx);
			BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "mode", gWifi_settings.radio[radio_idx].mode, "Unable to add radio %d mode", radio_idx);
			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "txpower", gWifi_settings.radio[radio_idx].txpower, "Unable to add radio %d txpower", radio_idx);
			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "rtscts", gWifi_settings.radio[radio_idx].rtscts, "Unable to add radio %d rtscts", radio_idx);
			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "disable_lower_rates", gWifi_settings.radio[radio_idx].disable_lower_rates, "Unable to add radio %d disable_lower_rates", radio_idx);

			/* *.disable_lower_rates is _not_ an int, it is an enum. We check if it's a valid
			 * array index because we are using it to index into an enum to string translation.
			 */
			if (CHECK_RANGE(gWifi_settings.radio[radio_idx].disable_lower_rates, 0, __PHY_RATE_ENUM_MAX - 1))
				BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "disable_lower_rates_enum_str", wifi_phy_rate_mode_strings[gWifi_settings.radio[radio_idx].disable_lower_rates], "Unable to add radio %d disable_lower_rates_enum_str", radio_idx);

			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "minimum_data_rate", gWifi_settings.radio[radio_idx].minimum_data_rate, "Unable to add radio %d minimum_data_rate", radio_idx);
			BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "mesh_enable", gWifi_settings.radio[radio_idx].mesh_enable, "Unable to add radio %d mesh_enable", radio_idx);
		}

		blobmsg_close_table(dump_blobmsg, radio_cookie);
		radio_cookie = NULL;
	}
}

static void wifi_dump_mesh_settings(struct blob_buf *dump_blobmsg, bool secure)
{
	NULL_ASSERT(VOID_RETURN_VALUE, dump_blobmsg);

	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "protocol", gWifi_settings.mesh.protocol, "Unable to add mesh protocol");

	void *batman_cookie = blobmsg_open_table(dump_blobmsg, "batman");

	if (!batman_cookie) {
		debug_msg_warn("Unable to add mesh batman settings to dump structure");
		return;
	}

	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "hop_penalty", gWifi_settings.mesh.batman.hop_penalty, "Unable to add mesh batman hop_penalty");
	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "gw_stickiness", gWifi_settings.mesh.batman.gw_stickiness, "Unable to add mesh batman gw_stickiness");
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "bridge_loop_avoidance", gWifi_settings.mesh.batman.bridge_loop_avoidance, "Unable to add mesh batman bridge_loop_avoidance");

	blobmsg_close_table(dump_blobmsg, batman_cookie);
	batman_cookie = NULL;

	if (secure)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "key", gWifi_settings.mesh.key, "Unable to add mesh key");
}

static void wifi_dump_settings(struct blob_buf *dump_blobmsg, bool secure)
{
	NULL_ASSERT(VOID_RETURN_VALUE, dump_blobmsg);

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "enable", gWifi_settings.enable, "Unable to add wifi enable flag");
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "ap_scan", gWifi_settings.ap_scan, "Unable to add wifi ap_scan flag");
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "delayed_wifi", gWifi_settings.delayed_wifi, "Unable to add delayed wifi flag");
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "save_orphans", gWifi_settings.save_orphans, "Unable to add save orphans flag");
	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "radio_override", gWifi_settings.radio_override, "Unable to add radio_override nonce");
	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "override_reason", gWifi_settings.override_reason, "Unable to add override_reason");

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "reg_outdoor", gWifi_settings.reg_outdoor, "Unable to add outdoor AP flag");
	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "reg_country", gWifi_settings.reg_country, "Unable to add regulatory country flag");

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "dfs_enable", gWifi_settings.dfs.enable, "Unable to add DFS enabled flag");

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "dpi_enable", gWifi_settings.dpi_enable, "Unable to add 'dpi_enable' flag");

	if (gWifi_settings.dfs.enable) {
		void *dfs_channels_cookie = blobmsg_open_array(dump_blobmsg, "dfs_channels");

		if (dfs_channels_cookie) {
			for (unsigned int i = 0; i < gWifi_settings.dfs.channel_count; ++i)
				BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "channel", gWifi_settings.dfs.channel[i], "Unable to add DFS channel idx %d", i);

			blobmsg_close_array(dump_blobmsg, dfs_channels_cookie);
			dfs_channels_cookie = NULL;
		}
	}

	void *ssid_cookie = blobmsg_open_array(dump_blobmsg, "ssids");

	if (!ssid_cookie) {
		debug_msg_warn("Unable to add ssid settings array");
	} else {
		wifi_dump_ssid_settings(dump_blobmsg, secure);
		blobmsg_close_array(dump_blobmsg, ssid_cookie);
		ssid_cookie = NULL;
	}

	void *radio_cookie = blobmsg_open_array(dump_blobmsg, "radios");

	if (!radio_cookie) {
		debug_msg_warn("Unable to add radio settings array");
	} else {
		wifi_dump_radio_settings(dump_blobmsg);
		blobmsg_close_array(dump_blobmsg, radio_cookie);
		radio_cookie = NULL;
	}

	void *mesh_cookie = blobmsg_open_table(dump_blobmsg, "mesh");

	if (!mesh_cookie) {
		debug_msg_warn("Unable to add mesh settings table");
	} else {
		wifi_dump_mesh_settings(dump_blobmsg, secure);
		blobmsg_close_table(dump_blobmsg, mesh_cookie);
		mesh_cookie = NULL;
	}

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "presence_enable", gWifi_settings.presence_enable, "Unable to add presence analytics enable flag");

	if (gWifi_settings.presence_enable)
		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "presence_interval", gWifi_settings.presence_period, "Unable to add presence analytics report interval");

	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "node_id", gWifi_settings.node_id, "Unable to add node ID");

	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "wired_client_ssid", gWifi_settings.wired_client_ssid, "Unable to add 'wired_client_ssid'");
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "disable_wired_client", gWifi_settings.disable_wired_client, "Unable to add 'disable_wired_client'");

	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "orphan_connect_bssid", gWifi_settings.orphan_connect_bssid, "Unable to add 'orphan_connect_bssid'");

	char *radio_band = platform_wireless_get_radio_band(gWifi_settings.orphan_connect_radio);

	if (!radio_band)
		debug_msg_notice("Unable to determine band for gWifi_settings.orphan_connect_radio %d", gWifi_settings.orphan_connect_radio);
	else
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "orphan_connect_radio", radio_band, "Unable to add 'orphan_connect_radio'");

	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "scanning_period", gWifi_settings.scanning_period, "Unable to add scanning period");
	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "scanning_phy", gWifi_settings.scanning_phy, "Unable to add scanning phy");

	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "survey_phy", gWifi_settings.survey_phy, "Unable to add survey phy");
	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "survey_period", gWifi_settings.survey_period, "Unable to add survey period");
	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "survey_dwell_time", gWifi_settings.survey_dwell_time, "Unable to add survey dwell time");

	int ant_type = gWifi_settings.antenna_type;

	if (OUT_OF_RANGE(ant_type, 0, __ANTENNA_MAX - 1))
		ant_type = 0;

	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "antenna_type", gAntennas[ant_type], "Unable to add antenna type");

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "recover_config_errors", gWifi_settings.recover_config_errors, "Unable to add 'recover_config_errors' flag");
}

/* dump_blobmsg to be verified by caller */
static void wifi_dump_lonely_state(struct blob_buf *dump_blobmsg)
{
	BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "lonely_trigger_count", gWifi_state.lonely_trigger_count, "Unable to add 'lonely_trigger_count'");
}

static void wifi_dump_mesh_data(struct blob_buf *dump_blobmsg)
{
	BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "upstream_state", upstream_state_to_string(gDatto_net_state.inet_test.upstream_state), "Unable to add 'upstream_state' member");

	if (!gWifi_state.mesh.gateway_mac)
		return;

	if (gWifi_state.mesh.gateway_mac)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway", gWifi_state.mesh.gateway_mac, "Unable to add 'gateway' member");

	if (gWifi_state.mesh.gateway_quality)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_quality", gWifi_state.mesh.gateway_quality, "Unable to add 'gateway_quality' member");

	if (gWifi_state.mesh.gateway_next_hop_mesh_peer_mac_addr[0]) {
		char temp_str[MAC_STR_LENGTH + 1] = {0};

		snprintf(temp_str, sizeof(temp_str), MAC_FMT_PRINT, MAC_ARG_PRINT(gWifi_state.mesh.gateway_next_hop_mesh_peer_mac_addr));
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_next_hop_mesh_peer_mac_addr", temp_str, "Unable to add 'gateway_next_hop_mesh_peer_mac_addr' member");
	}

	if (gWifi_state.mesh.gateway_interface)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_interface", gWifi_state.mesh.gateway_interface, "Unable to add 'gateway_interface' member");

	if (gWifi_state.mesh.gateway_route)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_route", gWifi_state.mesh.gateway_route, "Unable to add 'gateway_route' member");

	if (gWifi_state.mesh.gateway_latency)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_latency", gWifi_state.mesh.gateway_latency, "Unable to add 'gateway_latency' member");

	if (gWifi_state.mesh.gateway_rx_bitrate)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_rx_bitrate", gWifi_state.mesh.gateway_rx_bitrate, "Unable to add 'gateway_rx_bitrate' member");

	if (gWifi_state.mesh.gateway_tx_bitrate)
		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "gateway_tx_bitrate", gWifi_state.mesh.gateway_tx_bitrate, "Unable to add 'gateway_tx_bitrate' member");
}

static void wifi_dump_dfs_data(struct blob_buf *dump_blobmsg)
{
	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "dfs_event_detected", gWifi_state.dfs_event_detected, "Unable to add 'dfs_event_detected' member");

	void *dfs_usable_cookie = blobmsg_open_array(dump_blobmsg, "dfs_usable");

	if (!dfs_usable_cookie) {
		debug_msg_notice("Unable to create 'dfs_usable' object");
		return;
	}

	for (int i = 0; (i < DFS_MAX_CHANNEL) && gWifi_state.chan_state[i].freq; ++i) {
		if ((gWifi_state.chan_state[i].state == NL80211_DFS_USABLE) || (gWifi_state.chan_state[i].state == NL80211_DFS_AVAILABLE)) {
			int current_channel = sys_freq2chan(gWifi_state.chan_state[i].freq);

			BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "channel", current_channel, "Unable to add 'channel' member");
		}
	}

	blobmsg_close_array(dump_blobmsg, dfs_usable_cookie);
}

int wifi_dump_state(bool secure, struct blob_buf *dump_blobmsg)
{
	NULL_ASSERT(UBUS_STATUS_UNKNOWN_ERROR, dump_blobmsg);

	/* Settings Dump */
	void *settings_cookie = blobmsg_open_table(dump_blobmsg, "settings");

	if (!settings_cookie) {
		debug_msg_err("Unable to create 'settings' object for dump_state");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	wifi_dump_settings(dump_blobmsg, secure);

	blobmsg_close_table(dump_blobmsg, settings_cookie);
	settings_cookie = NULL;

	/* State Dump */
	void *state_cookie = blobmsg_open_table(dump_blobmsg, "state");

	if (!state_cookie) {
		debug_msg_err("Unable to create 'state' object for dump_state");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	BLOBMSG_ADD_CALL_WARN(u8, dump_blobmsg, "delayed_wifi", (!!gWifi_state.delayed_wifi_file[0]), "Unable to add 'delayed_wifi' member");

	wifi_dump_neighbor_list(dump_blobmsg);
	wifi_dump_lonely_state(dump_blobmsg);
	wifi_dump_mesh_data(dump_blobmsg);
	wifi_dump_scanning_state(dump_blobmsg);
	wifi_dump_dfs_data(dump_blobmsg);
	wifi_dump_survey_state(dump_blobmsg);
	wifi_dump_hapd_ft_auth_bridges_state(dump_blobmsg);

	blobmsg_close_table(dump_blobmsg, state_cookie);
	state_cookie = NULL;

	return UBUS_STATUS_OK;
}
