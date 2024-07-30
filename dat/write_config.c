/***
 *
 * Copyright (C) 2022 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "settings.h"
#include "wifi/bridge.h"
#include "wifi/settings/delayed_wifi.h"
#include "wifi/settings/ssid.h"
#include "wifi/settings/uci_addrs.h"
#include "wifi/settings/write_config.h"
#include "wifi/validation.h"

#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <string.h>

#include <openssl/md5.h>

#include <libomcommon/common.h>
#include <libomcommon/debug_msg.h>
#include <libomcommon/file.h>
#include <libomcommon/str_util.h>
#include <libomcommon/uci.h>

#include <libfwcore/platform/wireless.h>

/* This is a list of the valid minimum basic and supported data rates we can set into the radio.
 * Each number is in Kbps.
 */
static const int data_rate_list[] = { 1000, 2000, 5500, 6000, 9000, 11000, 12000, 18000, 24000 };
static const char *data_rate_string_list_in_Kbps[] = { "1000", "2000", "5500", "6000", "9000", "11000", "12000", "18000", "24000" };
static const bool data_rate_is_basic_rate[] = { true, true, true, true, false, true, true, false, true };

_Static_assert(ARRAY_SIZE(data_rate_string_list_in_Kbps) == ARRAY_SIZE(data_rate_list), "The data_rate_string_list_in_Kbps array of strings must have the same number of elements as the data_rate_list array of ints");
_Static_assert(ARRAY_SIZE(data_rate_is_basic_rate) == ARRAY_SIZE(data_rate_list), "The data_rate_is_basic_rate array of bools must have the same number of elements as the data_rate_list array of ints");

#define data_rate_min_value_5GHz	6000

/* 11000 Kbps is an allowed data rate for 2.4GHz, but not for 5GHz, so always skip when writing it
 * out to the list
 */
#define skip_data_rate_5GHz			11000

/*
 * Generates the key for an orphan interface.
 * bssid	- The BSSID of the orphan_connect AP as a string (won't be modified)
 * key		- The key to use, must be a string of at least 12 characters in length.
 */
static void wifi_generate_orphan_key(const char *bssid, char *key)
{
	NULL_ASSERT2(VOID_RETURN_VALUE, bssid, key);

	/* MAC + newline + null termination */
	char orphan_bssid[MAC_STR_LENGTH + 2] = {0};

	size_t len = strlen(bssid);

	if (sizeof(orphan_bssid) < len)
		len = sizeof(orphan_bssid);

	/* Key is based on the upper case BSSID */
	for (unsigned int i = 0; i < len; ++i)
		orphan_bssid[i] = toupper(bssid[i]);

	/* Add a newline at the end of the MAC */
	orphan_bssid[MAC_STR_LENGTH] = '\n';
	orphan_bssid[MAC_STR_LENGTH + 1] = '\0';

	unsigned char md5_digest[MD5_DIGEST_LENGTH] = {0};
	char md5sum_full[(2 * MD5_DIGEST_LENGTH) + 1] = {0};

	MD5((unsigned char *)orphan_bssid, strlen(orphan_bssid), md5_digest);

	for (int i = 0; i < MD5_DIGEST_LENGTH; ++i)
		sprintf(&md5sum_full[i * 2], "%02hhx", md5_digest[i]);

	int j = 0;

	for (unsigned int i = 0; i < (sizeof(md5sum_full) - 1); i += 3)
		key[j++] = md5sum_full[i];
}

bool wifid_minimum_data_rate_is_valid(int minimum_data_rate)
{
	/* First ensure this is a valid data rate sent down from the cloud */
	for (uint32_t idx = 0; idx < ARRAY_SIZE(data_rate_list); ++idx) {
		if (data_rate_list[idx] == minimum_data_rate)
			return true;
	}

	return false;
}

static void write_custom_minimum_data_rate_list_uci(struct wifi_settings *parsed_settings, int radio_idx, bool is_5GHz)
{
	NULL_ASSERT(VOID_RETURN_VALUE, parsed_settings);

	int minimum_data_rate = parsed_settings->radio[radio_idx].minimum_data_rate;

	if (!wifid_minimum_data_rate_is_valid(minimum_data_rate)) {
		debug_msg_warn("Unable to determine which basic and supported rates to use for PHY %d, will use all rates.", radio_idx);
		return;
	}

	bool is_first_valid_data_rate = true;

	for (uint32_t idx = 0; idx < ARRAY_SIZE(data_rate_list); ++idx) {
		if (data_rate_list[idx] < minimum_data_rate)
			continue;

		if (is_5GHz && minimum_data_rate < data_rate_min_value_5GHz) {
			debug_msg_info("Set minimum_data_rate for radio %d is below the allowed 5GHz minimum data rate (%i)", radio_idx, data_rate_min_value_5GHz);
			continue;
		}

		/* The 11000 Kbps data rate is supported for the 2.4GHz band but not for 5GHz. So skip this
		 * data rate if this is for a 5Ghz radio.
		 */
		if (is_5GHz && data_rate_list[idx] == skip_data_rate_5GHz)
			continue;

		/* We can't have a minimum_data_rate that is lower than the first available basic rate,
		 * so only allow this rate if it is not the first one.
		 */
		if (!data_rate_is_basic_rate[idx] && is_first_valid_data_rate)
			continue;

		ng_uci_add_list(gDatto_net_state.uci_ctx, data_rate_string_list_in_Kbps[idx], uci_addr_radio_supported_rates, radio_idx);

		if (data_rate_is_basic_rate[idx]) {
			ng_uci_add_list(gDatto_net_state.uci_ctx, data_rate_string_list_in_Kbps[idx], uci_addr_radio_basic_rate, radio_idx);
			ng_uci_add_list(gDatto_net_state.uci_ctx, data_rate_string_list_in_Kbps[idx], uci_addr_mesh_basic_rates, radio_idx);
		}

		/* If this is the first valid data rate, we will want to set this as the mcast_rate in
		 * ssid.c, so save this setting for later
		 */
		if (is_first_valid_data_rate)
			parsed_settings->radio[radio_idx].mcast_rate = data_rate_list[idx];

		is_first_valid_data_rate = false;
	}

	/* These data rate are always supported when we disable lower rates */
	ng_uci_add_list(gDatto_net_state.uci_ctx, "36000", uci_addr_radio_supported_rates, radio_idx);
	ng_uci_add_list(gDatto_net_state.uci_ctx, "48000", uci_addr_radio_supported_rates, radio_idx);
	ng_uci_add_list(gDatto_net_state.uci_ctx, "54000", uci_addr_radio_supported_rates, radio_idx);
}

/* Returns:
 *	-1 on failure
 *	0 if the radio is disabled (or scanning)
 *	1 if the radio is enabled
 */
static int wifid_write_radio_config(struct wifi_settings *parsed_settings, int radio_idx)
{
	NULL_ASSERT(-1, parsed_settings);

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	if (OUT_OF_RANGE(radio_idx, 0, ap_radio_max - 1))
		return -1;

	ng_uci_delete(gDatto_net_state.uci_ctx, "wireless.mesh%d.pre_config", radio_idx);

	/* Delete all UCI settings for scanning radios */
	if (platform_wireless_radio_is_scanning(radio_idx)) {
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_WIRELESS_RADIO, radio_idx);
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_WIRELESS_MESH, radio_idx);
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_WIRELESS_ORPHAN, radio_idx);
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_WIRELESS_ORPH_CONN, radio_idx);

		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx)
			ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_WIRELESS_AP, radio_idx, ssid_idx + 1);

		/* Set the scanning period/phy */
		ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->scanning_period, "%s", uci_addr_u80211d_scan_period);
		ng_uci_set_int(gDatto_net_state.uci_ctx, radio_idx, "%s", uci_addr_u80211d_scan_phy);

		/* Set the survey period, dwell time, and phy */
		ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->survey_period, "%s", uci_addr_u80211d_survey_period);
		ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->survey_dwell_time, "%s", uci_addr_u80211d_survey_dwell_time);
		ng_uci_set_int(gDatto_net_state.uci_ctx, radio_idx, "%s", uci_addr_u80211d_survey_phy);

		return 0;
	}

	if (!parsed_settings->radio[radio_idx].enable)
		return 0;

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->radio[radio_idx].txpower, uci_addr_radio_txpower, radio_idx);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->radio[radio_idx].rtscts, uci_addr_radio_rts, radio_idx);
	ng_uci_set_int(gDatto_net_state.uci_ctx, !parsed_settings->ap_scan, uci_addr_radio_noscan, radio_idx);

	ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_radio_supported_rates, radio_idx);
	ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_radio_basic_rate, radio_idx);
	ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_mesh_basic_rates, radio_idx);

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->radio[radio_idx].disable_lower_rates, uci_addr_radio_disable_lower_rates, radio_idx);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->radio[radio_idx].minimum_data_rate, uci_addr_radio_minimum_data_rate, radio_idx);

	/* OpenWRT 21.02 and above defaults to disabling legacy rates, so explicitly enable them.
	 * If we don't want these rates, specifying which rates to use below will override this option.
	 */
	ng_uci_set_int(gDatto_net_state.uci_ctx, 1, uci_addr_radio_legacy_rates, radio_idx);

	/* All of the rates in this section are expressed in kbps, per UCI requirements */
	switch (parsed_settings->radio[radio_idx].disable_lower_rates) {
	case PHY_RATE_DISABLE_11B_RATES:
		/* Add the 11a/g rates if only disabling 11b rates */
		ng_uci_add_list(gDatto_net_state.uci_ctx, "6000", uci_addr_radio_supported_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "9000", uci_addr_radio_supported_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "12000", uci_addr_radio_supported_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "18000", uci_addr_radio_supported_rates, radio_idx);

		ng_uci_add_list(gDatto_net_state.uci_ctx, "6000", uci_addr_radio_basic_rate, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "12000", uci_addr_radio_basic_rate, radio_idx);

		ng_uci_add_list(gDatto_net_state.uci_ctx, "6000", uci_addr_mesh_basic_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "12000", uci_addr_mesh_basic_rates, radio_idx);

		/* fall through */
	case PHY_RATE_DISABLE_ALL_LOWER_RATES:
		/* Only the highest of rates */
		ng_uci_add_list(gDatto_net_state.uci_ctx, "24000", uci_addr_radio_supported_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "36000", uci_addr_radio_supported_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "48000", uci_addr_radio_supported_rates, radio_idx);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "54000", uci_addr_radio_supported_rates, radio_idx);

		ng_uci_add_list(gDatto_net_state.uci_ctx, "24000", uci_addr_radio_basic_rate, radio_idx);

		ng_uci_add_list(gDatto_net_state.uci_ctx, "24000", uci_addr_mesh_basic_rates, radio_idx);
		break;
	case PHY_RATE_DISABLE_CUSTOM_RATES:
		if (parsed_settings->radio[radio_idx].minimum_data_rate > 24000) {
			debug_msg_info("Parsed minimum_data_rate is larger the max of 24000 Kbps (%i) capping value at 24000 Kbps.");
			parsed_settings->radio[radio_idx].minimum_data_rate = 24000;
		}

		if (sys_is_valid_channel_5GHz(parsed_settings->radio[radio_idx].channel))
			write_custom_minimum_data_rate_list_uci(parsed_settings, radio_idx, true);
		else if (sys_is_valid_channel_2_4GHz(parsed_settings->radio[radio_idx].channel))
			write_custom_minimum_data_rate_list_uci(parsed_settings, radio_idx, false);
		else
			debug_msg_info("Unable to determine if PHY %d on channel %d is 5GHz or 2.4GHz, won't limit supported or basic rates", radio_idx, parsed_settings->radio[radio_idx].channel);

		break;
	}

	/* Save orphans */
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->save_orphans, uci_addr_orphan_enable, radio_idx);

	if (parsed_settings->save_orphans) {
		/* MAC + newline + null termination */
		char orphan_bssid[MAC_STR_LENGTH + 2] = {0};
		char orphan_key[12] = {0}; // md5sum is 32 characters, we use 11 of them

		ng_uci_data_get_val(orphan_bssid, sizeof(orphan_bssid), uci_addr_orphan_macaddr, radio_idx);

		wifi_generate_orphan_key(orphan_bssid, orphan_key);

		ng_uci_set_string(gDatto_net_state.uci_ctx, orphan_key, uci_addr_orphan_key, radio_idx);
	}

	/* Orphan connect iface */
	if (parsed_settings->orphan_connect_bssid[0] && (radio_idx == parsed_settings->orphan_connect_radio)) {
		char orphan_key[12] = {0}; // md5sum is 32 characters, we use 11 of them

		wifi_generate_orphan_key(parsed_settings->orphan_connect_bssid, orphan_key);

		ng_uci_set_string(gDatto_net_state.uci_ctx, orphan_key, uci_addr_orph_conn_key, radio_idx);
		ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->orphan_connect_bssid, uci_addr_orph_conn_bssid, radio_idx);
		ng_uci_set_int(gDatto_net_state.uci_ctx, 1, uci_addr_orph_conn_enable, radio_idx);
	} else {
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_orph_conn_key, radio_idx);
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_orph_conn_bssid, radio_idx);
		ng_uci_set_int(gDatto_net_state.uci_ctx, 0, uci_addr_orph_conn_enable, radio_idx);
	}

	return 1;
}

int wifid_write_config(struct wifi_settings *parsed_settings)
{
	NULL_ASSERT(-1, parsed_settings);

	char delayed_wifi_file[128] = {0};
	struct timespec monotonic_time = {0};

	if (clock_gettime(CLOCK_MONOTONIC, &monotonic_time) < 0) {
		debug_msg_err("Unable to get time to generate unique delayed wifi file");
		return -1;
	}

	do {
		snprintf(delayed_wifi_file, sizeof(delayed_wifi_file), "/tmp/delayed_wifi_%" PRId64, ++monotonic_time.tv_sec);
	} while (file_exists(delayed_wifi_file));

	if (wifid_write_delayed_wifi_config(parsed_settings, delayed_wifi_file) < 0) {
		debug_msg_err("Unable to write out delayed wifi settings");
		return -1;
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->presence_enable, "%s", uci_addr_prequestd_enable);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->presence_period, "%s", uci_addr_prequestd_interval);

	/* Clear out the presence interface list.  We will re-add all enable ap ifaces below */
	ng_uci_delete(gDatto_net_state.uci_ctx, "%s", uci_addr_prequestd_interface);

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		/* int ret = */
		wifid_write_radio_config(parsed_settings, radio_idx);

		bool ap_iface_added_to_prequestd = false;

		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
			int ret = wifid_write_ap_iface_config(parsed_settings, ssid_idx, radio_idx);

			/* Only add the ap iface to prequestd if it was enabled */
			if (ret != 1)
				continue;

			if (!ap_iface_added_to_prequestd) {
				char ap_iface[IFNAMSIZ] = {0};

				snprintf(ap_iface, sizeof(ap_iface), "ap%d_%d", radio_idx, ssid_idx + 1);
				ng_uci_add_list(gDatto_net_state.uci_ctx, ap_iface, "%s", uci_addr_prequestd_interface);
				ap_iface_added_to_prequestd = true;
			}
		}
	}

	uint16_t ip_id = get_ip_id(parsed_settings->node_id);

	char mesh_gw_str[32] = {0};

	/* FORM: mesh_gw = ip_id - (ssid + 1) * 4, where normal SSIDs are 1-based and mesh is 0 */
	int mesh_gw = ip_id - (0 + 1) * 4;

	snprintf(mesh_gw_str, sizeof(mesh_gw_str), "10.%d.%d.1", (uint8_t) (mesh_gw >> 8), (uint8_t) mesh_gw);
	ng_uci_set_string(gDatto_net_state.uci_ctx, mesh_gw_str, "network.mesh_gw.ipaddr");

	snprintf(mesh_gw_str, sizeof(mesh_gw_str), "10.%d.%d.1/22", (uint8_t) (mesh_gw >> 8), (uint8_t) mesh_gw);
	for (int wired_bridge = 0; wired_bridge < WIRED_MAX; ++wired_bridge) {
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_firewall_wired_masq_src, wired_bridge);
		ng_uci_add_list(gDatto_net_state.uci_ctx, mesh_gw_str, uci_addr_firewall_wired_masq_src, wired_bridge);
	}

	// Set lan dns rebind protection
	bool rebind_protection = 1;

	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		if (parsed_settings->ssid[ssid_idx].rebind_protection == 0) {
			rebind_protection = 0;
			break;
		}
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, rebind_protection, DATTO_NET_UCI_DHCP ".lan_dns.rebind_protection");

	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx)
		wifid_write_ssid_config(parsed_settings, ssid_idx);

	ng_uci_set_int(gDatto_net_state.uci_ctx, !platform_wireless_get_scanning_support(), "%s", uci_addr_u80211d_ap_force);

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->delayed_wifi, "%s", uci_addr_delayed_wifi);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->node_id, "%s", uci_addr_fw_core_node_id);

	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->radio_override, "%s", uci_addr_radio_override);
	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->override_reason, "%s", uci_addr_override_reason);

	set_udsplash_logout_firewall(gDatto_net_state.inet_test.upstream_state, parsed_settings);
	set_uds_ifaces(gDatto_net_state.inet_test.upstream_state, false, parsed_settings);

	/* Close out the UCI context, and create a new one to ensure our changes are flushed out */
	if (gDatto_net_state.uci_ctx)
		uci_free_context(gDatto_net_state.uci_ctx); /* NOT explicitly set to NULL, immediate reassignment */

	gDatto_net_state.uci_ctx = uci_alloc_context();
	if (!gDatto_net_state.uci_ctx)
		debug_msg_warn("Failed to create new UCI context for datto_net");

	return 0;
}
