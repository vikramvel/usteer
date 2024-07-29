/***
 *
 * Copyright (C) 2022-2024 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "main.h"
#include "rtnl.h"
#include "settings.h"
#include "wifi/ap_scan.h"
#include "wifi/ap_survey.h"
#include "wifi/bridge.h"
#include "wifi/dfs.h"
#include "wifi/mesh.h"
#include "wifi/neighbors.h"
#include "wifi/settings/delayed_wifi.h"
#include "wifi/settings/hostapd_ft_mgmt.h"
#include "wifi/settings/reload_config.h"
#include "wifi/settings/uci_addrs.h"
#include "wired/online.h"

#include <libomcommon/file.h>
#include <libomcommon/led.h>
#include <libomcommon/uci.h>

#include <libfwcore/platform/wireless.h>
#include <libfwcore/reboot.h>

#include <libubox/avl-cmp.h>

struct wifi_state gWifi_state = {0};

static void reload_config_acl_update(struct vlist_tree OM_UNUSED(*tree), struct vlist_node OM_UNUSED(*new_node), struct vlist_node *old_node)
{
	/*
	 * At any time in the reload process, if we get a call where one of the nodes is NULL
	 * and the other is not, then that can be a trigger for an ACL list reload into hostapd.
	 *
	 * A better location to do this detection would be in the netifd scripts, but this
	 * could potentially be a workaround.
	 *
	 * if ((!!new_node) != (!!old_node))
	 */

	/* Free an old_node provided here, because it has been removed from the vlist and the memory
	 * will be lost otherwise
	 */
	if (old_node) {
		struct acl_list_entry *old_acl_entry = container_of(old_node, struct acl_list_entry, vlist_node);

		free(old_acl_entry); /* NOT explicitly set to NULL on next line, immediate return */
		return;
	}
}

static void wifi_init_state(void)
{
	if (gWifi_state.delayed_wifi_file[0])
		wifid_cancel_delayed_wifi();

	if (gWifi_state.new_delayed_wifi_file[0])
		unlink(gWifi_state.new_delayed_wifi_file);

	wifid_free_neighbor_list(gWifi_state.neighbors);		/* Explicitly set to NULL following group of frees */
	wifid_free_neighbor_list(gWifi_state.new_neighbors);	/* Explicitly set to NULL following group of frees */

	gWifi_state.neighbors = NULL;
	gWifi_state.new_neighbors = NULL;

	uloop_timeout_cancel(&gWifi_state.neighbor_timer);

	/* Create the batman VLANs for bridge to lan, since they float between bridges */
	ng_rtnl_vlan_add("bat0", 31);
	ng_rtnl_vlan_add("bat0", 32);
	ng_rtnl_vlan_add("bat0", 33);
	ng_rtnl_vlan_add("bat0", 34);

	wifi_init_scan_state();

	wifi_init_survey_state();

	ubus_lookup(&gDatto_net_ubus_conn.ctx, NULL, u80211d_register_ubus_subscriber_cb, NULL);

	wifi_restore_config_enabled_interfaces(true);

	restart_dfs_event_listener();

	if (gWifi_state.lldp_listener.obj_id) {
		debug_msg_info("Unsubscribed from LLDP notifications");
		ubus_unsubscribe(&gDatto_net_ubus_conn.ctx, &gWifi_state.lldp_listener.subscriber, gWifi_state.lldp_listener.obj_id);
	}

	if (gWifi_state.lldp_listener.subscriber.obj.id) {
		ubus_unregister_subscriber(&gDatto_net_ubus_conn.ctx, &gWifi_state.lldp_listener.subscriber);
		gWifi_state.lldp_listener.subscriber.obj.id = 0;
		debug_msg_info("Unregistered LLDP subscriber");
	}
	/* Flush the list of hapd instances, re-enumerate list
	 * The ft_auth_bridge for each enumerated instance will be
	 * handled during a reload config.
	 */
	wifi_flush_hapd_instance_list(&gWifi_state);
	wifi_enumerate_hapd_instances_add_to_list();
	uloop_timeout_cancel(&gWifi_state.update_hapd_instances_timer);

	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		if (gWifi_settings.ssid[ssid_idx].acl_vlist) {
			vlist_flush_all(gWifi_settings.ssid[ssid_idx].acl_vlist);
		} else {
			gWifi_settings.ssid[ssid_idx].acl_vlist = calloc(1, sizeof(struct vlist_tree));
			if (!gWifi_settings.ssid[ssid_idx].acl_vlist)
				debug_msg_err("Unable to allocate memory for ACL vlists");
			else
				vlist_init(gWifi_settings.ssid[ssid_idx].acl_vlist, avl_strcmp, reload_config_acl_update);
		}
	}
}

struct list_pop {
	struct wifi_settings *settings;
	int ssid_idx;
	int list_idx;
};

static int wifi_reload_ap_mgr_per_ssid_config(struct wifi_settings *new_settings, int ssid_idx)
{
	NULL_ASSERT(UBUS_STATUS_UNKNOWN_ERROR, new_settings);

	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX)) {
		debug_msg_err("Passed SSID index is out of range, passed %d vs max %d", ssid_idx, SSID_MAX);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}
	// TODO: reload config from usteer after ap_mgr remove
	ng_uci_data_get_val_bool(new_settings->ssid[ssid_idx].band_steering, uci_addr_ap_mgr_band_steering_enabled, ssid_idx + 1);
	ng_uci_data_get_val_bool(new_settings->ssid[ssid_idx].roaming_80211v, uci_addr_ap_mgr_roaming_enabled, ssid_idx + 1);

	return UBUS_STATUS_OK;
}

static int reload_config_populate_acl(char *name, void *arg)
{
	NULL_ASSERT2(-1, name, arg);

	struct list_pop *acl_pop = arg;

	if (!acl_pop->settings || (acl_pop->ssid_idx >= SSID_MAX) || (!acl_pop->settings->ssid[acl_pop->ssid_idx].acl_vlist)) {
		debug_msg_err("Invalid args to acl populate helper");
		return -1;
	}

	struct acl_list_entry *new_acl_entry = calloc(1, sizeof(*new_acl_entry));

	if (!new_acl_entry) {
		debug_msg_notice("Unable to allocate memory to add acl entry to ssid %d for '%s'", acl_pop->ssid_idx, name);
		return -1;
	}

	snprintf(new_acl_entry->mac, sizeof(new_acl_entry->mac), "%s", name);
	new_acl_entry->ssid_idx = acl_pop->ssid_idx;
	vlist_add(acl_pop->settings->ssid[acl_pop->ssid_idx].acl_vlist, &new_acl_entry->vlist_node, new_acl_entry->mac);

	return 0;
}

static int reload_config_populate_dns(char *name, void *arg)
{
	NULL_ASSERT2(-1, name, arg);

	struct list_pop *dns_pop = arg;

	if (!dns_pop->settings || (dns_pop->ssid_idx >= SSID_MAX)) {
		debug_msg_err("Invalid args to dns populate helper");
		return -1;
	}

	if (dns_pop->list_idx >= DNS_MAX) {
		debug_msg_info("Too many DNS entries for ssid %d in our structure, skipping", dns_pop->ssid_idx + 1);
		return 0;
	}

	snprintf(dns_pop->settings->ssid[dns_pop->ssid_idx].dns_server[dns_pop->list_idx], sizeof(dns_pop->settings->ssid[dns_pop->ssid_idx].dns_server[dns_pop->list_idx]), "%s", name);
	++dns_pop->list_idx;

	return 0;
}

static int reload_config_dfs_chanlist(char *name, void *arg)
{
	NULL_ASSERT2(-1, name, arg);

	struct dfs *dfs = arg;

	if (dfs->channel_count >= (DFS_MAX_CHANNEL)) {
		debug_msg_err("Only store %d channels, dropped %s", DFS_MAX_CHANNEL, name);
		return -1;
	}

	if (sscanf(name, "%d", &dfs->channel[dfs->channel_count]) != 1) {
		debug_msg_err("Invalid channel: %s", name);
		return -1;
	}

	/* Block weather radar channels */
	if (dfs->channel[dfs->channel_count] == 120 ||
		dfs->channel[dfs->channel_count] == 124 ||
		dfs->channel[dfs->channel_count] == 128) {
		debug_msg_warn("Rejecting weather radar channel %d from channel list", dfs->channel[dfs->channel_count]);
		dfs->channel[dfs->channel_count] = 44;

		/* Don't increment the chan_count, we're skipping this channel */
		return 0;
	}

	dfs->channel_count++;

	return 0;
}

static void datto_net_debug_set_level(void)
{
	int debug_level;

	if (ng_uci_data_get_val_int(&debug_level, "%s", uci_addr_datto_net_debug_level) < 0)
		debug_level = DEBUG_DEFAULT_LEVEL;

	debug_set_level(debug_level);
}

static void wifid_modify_presence_periodic_checkin(void)
{
	uint32_t cloud_comm_id;

	if (ubus_lookup_id(&gDatto_net_ubus_conn.ctx, "dnet.cloud_comm", &cloud_comm_id) != UBUS_STATUS_OK) {
		debug_msg_warn("Unable to lookup UBUS id for cloud_comm");
		return;
	}

	struct blob_buf periodic_checkin_buf = {0};

	if (blob_buf_init(&periodic_checkin_buf, 0)) {
		debug_msg_warn("Unable to initialize buffer to modify periodic checkin for presence");
		return;
	}

	if (blobmsg_add_string(&periodic_checkin_buf, "checkin_type", "presence")) {
		debug_msg_warn("Unable to add checkin type to periodic checkin request");
		blob_buf_free(&periodic_checkin_buf);
		return;
	}

	uint32_t period = (gWifi_settings.presence_enable) ? gWifi_settings.presence_period : 0;

	if (blobmsg_add_u32(&periodic_checkin_buf, "period", period)) {
		debug_msg_warn("Unable to add period to periodic checkin request");
		blob_buf_free(&periodic_checkin_buf);
		return;
	}

	struct ubus_request req = {0};

	/* We don't care about the result, so it's OK for the req to leave scope on exit. */
	if (ubus_invoke_async(&gDatto_net_ubus_conn.ctx, cloud_comm_id, "periodic_checkin", periodic_checkin_buf.head, &req) != UBUS_STATUS_OK)
		debug_msg_warn("Unable to modify periodic checkin for presence");

	blob_buf_free(&periodic_checkin_buf);
}

static void wifid_write_ctl_variant(struct wifi_settings *new_settings, bool fresh_start)
{
	NULL_ASSERT(VOID_RETURN_VALUE, new_settings);

	char *ctl_default_string = get_platform_ctl_variant("Default");
	char *new_ctl_country = get_platform_ctl_variant(new_settings->reg_country);
	char *new_ctl_antenna = "";
	char *new_ctl_outdoor = "";
	char new_ctl_variant[64] = {0};
	bool ctl_default = true;

	/*
	 * Friendly reminder that these CTL variants are just nicknames for the
	 * tables and may not correspond entirely with the governing regulatory
	 * agencies for the countries which use these tables.  These are
	 * essentially nicknames for these tables, and usually are named after the
	 * regulatory agency of the first country code to use them.
	 */

	if (!ctl_default_string) {
		debug_msg_warn("Unable to get default CTL variant country, defaulting to FCC");
		ctl_default_string = "FCC";
	}

	if (!new_ctl_country) {
		debug_msg_warn("Unable to get CTL variant for country %s, defaulting to FCC", new_settings->reg_country);
		new_ctl_country = "FCC";
	}

	if (strcmp(new_ctl_country, ctl_default_string))
		ctl_default = false;

	if (platform_wireless_get_external_antennas()) {
		new_ctl_antenna = "dipole-";

		if (new_settings->antenna_type == ANTENNA_PATCH) {
			new_ctl_antenna = "patch-";
			ctl_default = false;
		}
	}

	if (platform_wireless_get_outdoor_support()) {
		new_ctl_outdoor = platform_wireless_get_default_outdoor() ? "-outdoor" : "-indoor";

		if (new_settings->reg_outdoor != platform_wireless_get_default_outdoor()) {
			new_ctl_outdoor = new_settings->reg_outdoor ? "-outdoor" : "-indoor";
			ctl_default = false;
		}
	}

	snprintf(new_ctl_variant, sizeof(new_ctl_variant), "%s%s%s", new_ctl_antenna, new_ctl_country, new_ctl_outdoor);

	char ctl_variant_file[512] = {0};
	char *wifi_mode = platform_wireless_get_wifi_mode();

	/*
	 * Only set the CTL variant for broadcast radios.  If we set the ath10k variant on an AP840,
	 * it will apply that to the scanning radio, which causes it to not initialize properly.
	 */
	if (wifi_mode) {
		if (!strcmp("ac", wifi_mode))
			snprintf(ctl_variant_file, sizeof(ctl_variant_file), "ath10k_core ctlvariant=%s\n", new_ctl_variant);
		else if (!strcmp("ax", wifi_mode))
			snprintf(ctl_variant_file, sizeof(ctl_variant_file), "ath11k ctlvariant=%s\n", new_ctl_variant);
	}

	char *old_ctl_variant = NULL;
	bool overwrite = false;
	bool reboot = false;

	if (file_exists(CTL_VARIANT_FILE)) {
		if (file_read_bin(CTL_VARIANT_FILE, (unsigned char **) &old_ctl_variant, 0, sizeof(ctl_variant_file) - 1) < 0) {
			debug_msg_warn("Unable to read CTL variant modules file");
			return;
		}

		if (strncmp(old_ctl_variant, ctl_variant_file, sizeof(ctl_variant_file))) {
			debug_msg_notice("CTL variant changed! Overwriting, and reboot needed");
			overwrite = true;
			reboot = true;
		}

		free(old_ctl_variant); /* Explicitly set to NULL on following line */
		old_ctl_variant = NULL;
	} else if (!ctl_default) {
		debug_msg_notice("New non-default CTL variant '%s', writing and reboot needed", new_ctl_variant);
		overwrite = true;
		reboot = true;
	} else {
		debug_msg_notice("New default CTL variant '%s', writing needed", new_ctl_variant);
		overwrite = true;
	}

	if (fresh_start) {
		if (overwrite || reboot)
			debug_msg_notice("NOT changing CTL tables on fresh start to prevent changes on first boot in new image");

		return;
	}

	if (overwrite) {
		debug_msg_notice("Writing CTL table overrides to %s", CTL_VARIANT_FILE);
		file_write_string(CTL_VARIANT_FILE, ctl_variant_file);
	}

	if (reboot) {
		debug_msg_notice("Rebooting because CTL variant change");
		fw_core_reboot(&gDatto_net_ubus_conn.ctx, "CTL variant changed");
	}
}

int wifi_reload_config(bool fresh_start)
{
	if (fresh_start)
		wifi_init_state();

	struct wifi_settings new_settings = {0};

	/*
	 * Copy the acl_vlist head over from the old/existing settings structure so that we
	 * can take advantage of the update functionality to detect changes to the list.
	 */
	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx)
		new_settings.ssid[ssid_idx].acl_vlist = gWifi_settings.ssid[ssid_idx].acl_vlist;

	datto_net_debug_set_level();

	new_settings.enable = true;

	/* Default to negative, we will always get a positive ID from cloud config */
	new_settings.node_id = -1;

	/* Default to negative, so it is never actually a valid phy unless we see a scanning radio */
	new_settings.scanning_phy = -1;

	/* Default to negative, so it is never actually a valid phy unless we see a scanning radio */
	new_settings.survey_phy = -1;

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	free_scanning_results_list();

	ng_uci_data_get_val_bool(new_settings.dpi_enable, "udshape.general.matching_enable");

	bool device_has_scanning_radio_support = platform_wireless_get_scanning_support();

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		bool scanning_iface_registered = false;
		bool survey_iface_registered = false;
		char survey_ifname[IFNAMSIZ] = {0};

		if (platform_wireless_radio_is_scanning(radio_idx)) {
			add_scanning_iface("scan", false);
			scanning_iface_registered = true;

			ng_uci_data_get_val_int(&new_settings.scanning_period, "%s", uci_addr_u80211d_scan_period);
			if (!new_settings.scanning_period)
				new_settings.scanning_period = 60 * 60; /* Default to 1h scanning period */

			ng_uci_data_get_val_int(&new_settings.scanning_phy, "%s", uci_addr_u80211d_scan_phy);

			ng_uci_data_get_val_int(&new_settings.survey_phy, "%s", uci_addr_u80211d_survey_phy);
			ng_uci_data_get_val_int(&new_settings.survey_period, "%s", uci_addr_u80211d_survey_period);
			ng_uci_data_get_val_int(&new_settings.survey_dwell_time, "%s", uci_addr_u80211d_survey_dwell_time);
			if (!new_settings.survey_dwell_time)
				new_settings.survey_dwell_time = SURVEY_DWELL_TIME_DEFAULT;

			update_survey_list_by_radio_idx(radio_idx, "survey");
			survey_iface_registered = true;
		}

		int band = wifid_find_band(radio_idx);

		if (!IS_VALID_ARRAY_INDEX(band, BAND_MAX))
			continue;

		int orphan_connect_enable = 0;

		ng_uci_data_get_val_int(&orphan_connect_enable, uci_addr_orph_conn_enable, radio_idx);

		if (orphan_connect_enable) {
			ng_uci_data_get_val(new_settings.orphan_connect_bssid, sizeof(new_settings.orphan_connect_bssid), uci_addr_orph_conn_bssid, radio_idx);
			new_settings.orphan_connect_radio = radio_idx;
		}

		/* If enable isn't set, then it's default to on */
		new_settings.radio[radio_idx].enable = true;
		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].enable, uci_addr_radio_enable, radio_idx);

		if (!new_settings.radio[radio_idx].enable) {
			/* If changing to disabled, find and delete survey result */
			if (gWifi_settings.radio[radio_idx].enable) {
				struct wifi_survey_result_iface *survey_iface = find_survey_result_by_radio_idx(radio_idx);

				free_survey_result_iface(survey_iface); /* NOT explicitly set to NULL, variable exits scope immediately */
			}

			continue;
		}

		/* Pull in mesh key */
		ng_uci_data_get_val(new_settings.mesh.key, sizeof(new_settings.mesh.key), uci_addr_mesh_key, radio_idx);

		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].channel, uci_addr_radio_channel, radio_idx);
		ng_uci_data_get_val(new_settings.radio[radio_idx].mode, sizeof(new_settings.radio[radio_idx].mode), uci_addr_radio_htmode, radio_idx);
		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].txpower, uci_addr_radio_txpower, radio_idx);
		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].rtscts, uci_addr_radio_rts, radio_idx);

		/* Fetch mesh config_enable */
		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].mesh_enable, uci_addr_mesh_config_enable, radio_idx);

		ng_uci_data_get_val(new_settings.reg_country, sizeof(new_settings.reg_country), uci_addr_radio_country, radio_idx);

		if (wifid_radio_has_dfs(radio_idx)) {
			ng_uci_data_get_val_bool(new_settings.dfs.enable, uci_addr_radio_dfs_enable, radio_idx);

			new_settings.dfs.channel_count = 0;

			if (ng_uci_list_foreach_fmt(reload_config_dfs_chanlist, &new_settings.dfs, uci_addr_radio_chanlist, radio_idx) < 0) {
				debug_msg_err("Unable to parse dfs channel list");
				return UBUS_STATUS_UNKNOWN_ERROR;
			}
		}

		/* pull AP scan from "noscan", and invert it */
		ng_uci_data_get_val_bool(new_settings.ap_scan, uci_addr_radio_noscan, radio_idx);
		new_settings.ap_scan = !new_settings.ap_scan;

		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].disable_lower_rates, uci_addr_radio_disable_lower_rates, radio_idx);
		ng_uci_data_get_val_int(&new_settings.radio[radio_idx].minimum_data_rate, uci_addr_radio_minimum_data_rate, radio_idx);
		ng_uci_data_get_val_bool(new_settings.save_orphans, uci_addr_orphan_enable, radio_idx);

		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
			// use the AP config_enable UCI option for configuration information
			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].band[band].enable, uci_addr_ap_config_enable, radio_idx, ssid_idx + 1);

			if (!new_settings.ssid[ssid_idx].band[band].enable)
				continue;

			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].band[band].start_disabled, uci_addr_ap_start_disabled, radio_idx, ssid_idx + 1);

			/* Add the first apX_Y iface as a scanning iface */
			if (!scanning_iface_registered && !device_has_scanning_radio_support) {
				char ifname[IFNAMSIZ] = {0};

				snprintf(ifname, sizeof(ifname), "ap%d_%d", radio_idx, ssid_idx + 1);
				add_scanning_iface(ifname, true);
				scanning_iface_registered = true;
			}

			/* Add the first apX_Y iface as a survey iface, even if there is a scanning radio */
			if (!survey_iface_registered) {
				snprintf(survey_ifname, sizeof(survey_ifname), "ap%d_%d", radio_idx, ssid_idx + 1);
				update_survey_list_by_radio_idx(radio_idx, survey_ifname);
				survey_iface_registered = true;
			}

			ng_uci_data_get_val(new_settings.ssid[ssid_idx].band[band].ssid, sizeof(new_settings.ssid[ssid_idx].band[band].ssid), uci_addr_ap_ssid, radio_idx, ssid_idx + 1);

			ng_uci_data_get_val(new_settings.ssid[ssid_idx].key, sizeof(new_settings.ssid[ssid_idx].key), uci_addr_ap_key, radio_idx, ssid_idx + 1);
			ng_uci_data_get_val(new_settings.ssid[ssid_idx].enc, sizeof(new_settings.ssid[ssid_idx].enc), uci_addr_ap_encryption, radio_idx, ssid_idx + 1);

			/* set isolate for batman and uds */
			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].client_isolate, uci_addr_ap_isolate, radio_idx, ssid_idx + 1);

			/* RADIUS Auth */
			ng_uci_data_get_val(new_settings.ssid[ssid_idx].radius_server, sizeof(new_settings.ssid[ssid_idx].radius_server), uci_addr_ap_auth_server, radio_idx, ssid_idx + 1);
			ng_uci_data_get_val(new_settings.ssid[ssid_idx].radius_key, sizeof(new_settings.ssid[ssid_idx].radius_key), uci_addr_ap_auth_secret, radio_idx, ssid_idx + 1);
			ng_uci_data_get_val_int(&new_settings.ssid[ssid_idx].radius_port, uci_addr_ap_auth_port, radio_idx, ssid_idx + 1);

			/* RADIUS Accounting */
			ng_uci_data_get_val(new_settings.ssid[ssid_idx].radius_acct_server, sizeof(new_settings.ssid[ssid_idx].radius_acct_server), uci_addr_ap_acct_server, radio_idx, ssid_idx + 1);
			ng_uci_data_get_val(new_settings.ssid[ssid_idx].radius_acct_key, sizeof(new_settings.ssid[ssid_idx].radius_acct_key), uci_addr_ap_acct_secret, radio_idx, ssid_idx + 1);
			ng_uci_data_get_val_int(&new_settings.ssid[ssid_idx].radius_acct_port, uci_addr_ap_acct_port, radio_idx, ssid_idx + 1);

			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].hidden, uci_addr_ap_hidden, radio_idx, ssid_idx + 1);

			ng_uci_data_get_val(new_settings.ssid[ssid_idx].roaming_domain, sizeof(new_settings.ssid[ssid_idx].roaming_domain), uci_addr_ap_mobility_domain, radio_idx, ssid_idx + 1);

			// Needs to be 64 (roaming key) + 18 (MAC addr) + 18 (MAX addr) and delimiters for r1kh
			char roaming_key[128] = {0};

			ng_uci_data_get_val(roaming_key, sizeof(roaming_key), uci_addr_ap_r0kh, radio_idx, ssid_idx + 1);

			char *key_ptr = strrchr(roaming_key, ',');

			/* If we found a comma, move past it, and dump the key into our struct */
			if (key_ptr++)
				snprintf(new_settings.ssid[ssid_idx].roaming_key, sizeof(new_settings.ssid[ssid_idx].roaming_key), "%s", key_ptr);

			if (ng_uci_check_val("allow", uci_addr_ap_macfilter, radio_idx, ssid_idx + 1) == 1) {
				struct list_pop acl_pop = {
					.settings = &new_settings,
					.ssid_idx = ssid_idx
				};

				vlist_update(new_settings.ssid[ssid_idx].acl_vlist);
				ng_uci_list_foreach_fmt(reload_config_populate_acl, &acl_pop, uci_addr_ap_maclist, radio_idx, ssid_idx + 1);
				vlist_flush(new_settings.ssid[ssid_idx].acl_vlist);
			}

			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].neigh_report, uci_addr_ap_neighbor_reports, radio_idx, ssid_idx + 1);

			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].dynamic_vlan, uci_addr_ap_dynamic_vlan, radio_idx, ssid_idx + 1);

			ng_uci_data_get_val_int(&new_settings.ssid[ssid_idx].dtim_interval, uci_addr_ap_dtim_interval, radio_idx, ssid_idx + 1);
		}

		/* if we didn't select an AP interface, remove the current survey result from the list */
		if (!survey_iface_registered) {
			struct wifi_survey_result_iface *survey_iface = find_survey_result_by_radio_idx(radio_idx);

			free_survey_result_iface(survey_iface); /* NOT explicitly set to NULL, variable exits scope immediately */
		}
	}

	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].enable, uci_addr_ssid_enable, ssid_idx + 1);

		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].wifi_scheduling, uci_addr_ssid_wifi_scheduling, ssid_idx + 1);

		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].bridge_to_lan, uci_addr_ssid_bridge_to_lan, ssid_idx + 1);
		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].lan_block, uci_addr_firewall_datto_lan_block, ssid_idx + 1);

		ng_uci_data_get_val(new_settings.ssid[ssid_idx].smtp_redir, sizeof(new_settings.ssid[ssid_idx].smtp_redir), uci_addr_firewall_smtp_redirect, ssid_idx + 1);
		ng_uci_data_get_val_int(&new_settings.ssid[ssid_idx].vlan_tag, uci_addr_ssid_vid, ssid_idx + 1);

		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].dns_intercept, uci_addr_ssid_dns_intercept, ssid_idx + 1);

		/* Default to DNS cache is enabled, will be set to false below if appropriate */
		new_settings.ssid[ssid_idx].dns_cache_enable = true;

		if (ng_uci_sec_exists(DATTO_NET_UCI_DHCP_SSID_DNS, ssid_idx + 1) == 1) {
			ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].dns_cache_enable, DATTO_NET_UCI_DHCP_SSID_DNS ".cachesize", ssid_idx + 1);

			struct list_pop dns_pop = {
				.settings = &new_settings,
				.ssid_idx = ssid_idx,
				.list_idx = 0
			};

			ng_uci_list_foreach_fmt(reload_config_populate_dns, &dns_pop, uci_addr_dhcp_ssid_dns_server, ssid_idx + 1);
		}

		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].dhcp.enable, uci_addr_ssid_custom_dhcp, ssid_idx + 1);
		ng_uci_data_get_val(new_settings.ssid[ssid_idx].dhcp.gateway, sizeof(new_settings.ssid[ssid_idx].dhcp.gateway), uci_addr_ssid_ipaddr, ssid_idx + 1);
		ng_uci_data_get_val(new_settings.ssid[ssid_idx].dhcp.netmask, sizeof(new_settings.ssid[ssid_idx].dhcp.netmask), uci_addr_ssid_netmask, ssid_idx + 1);
		ng_uci_data_get_val_int(&new_settings.ssid[ssid_idx].dhcp.start, uci_addr_dhcp_ssid_start, ssid_idx + 1);
		ng_uci_data_get_val_int(&new_settings.ssid[ssid_idx].dhcp.num_leases, uci_addr_dhcp_ssid_limit, ssid_idx + 1);
		ng_uci_data_get_val(new_settings.ssid[ssid_idx].dhcp.lease_len, sizeof(new_settings.ssid[ssid_idx].dhcp.lease_len), uci_addr_dhcp_ssid_leasetime, ssid_idx + 1);
		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].rebind_protection, uci_addr_dhcp_ssid_rebind_protection, ssid_idx + 1);

		/* Reload ap_mgr specific per-ssid UCI options */
		wifi_reload_ap_mgr_per_ssid_config(&new_settings, ssid_idx);

		ng_uci_data_get_val_bool(new_settings.ssid[ssid_idx].shaping_enable, "udshape.ssid%d.shaping", ssid_idx + 1);

		char batctl_ap_isolate_cmd[512] = {0};

		snprintf(batctl_ap_isolate_cmd, sizeof(batctl_ap_isolate_cmd), "batctl vid 1%d ap_isolation %d; batctl vid 2%d ap_isolation %d; batctl vid 3%d ap_isolation %d", ssid_idx + 1, new_settings.ssid[ssid_idx].client_isolate, ssid_idx + 1, new_settings.ssid[ssid_idx].client_isolate, ssid_idx + 1, new_settings.ssid[ssid_idx].client_isolate);
		system(batctl_ap_isolate_cmd);
	}

	ng_uci_data_get_val_bool(new_settings.delayed_wifi, "%s", uci_addr_delayed_wifi);
	ng_uci_data_get_val_int(&new_settings.node_id, "%s", uci_addr_fw_core_node_id);

	ng_uci_data_get_val(new_settings.radio_override, sizeof(new_settings.radio_override), "%s", uci_addr_radio_override);
	ng_uci_data_get_val(new_settings.override_reason, sizeof(new_settings.override_reason), "%s", uci_addr_override_reason);

	int outdoor = platform_wireless_get_default_outdoor();

	ng_uci_data_get_val_int(&outdoor, "%s", uci_addr_outdoor);
	new_settings.reg_outdoor = !!outdoor;

	ng_uci_data_get_val_int(&new_settings.antenna_type, "%s", uci_addr_antenna);

	if (new_settings.radio_override[0]) {
		if (!strcmp(new_settings.override_reason, "lonely")) {
			update_led_flag(&gDatto_net_ubus_conn.ctx, "lonely", true);
			update_led_flag(&gDatto_net_ubus_conn.ctx, "orphan", false);
		} else {
			update_led_flag(&gDatto_net_ubus_conn.ctx, "lonely", false);
			update_led_flag(&gDatto_net_ubus_conn.ctx, "orphan", false);
		}
	} else if (new_settings.orphan_connect_bssid[0]) {
		update_led_flag(&gDatto_net_ubus_conn.ctx, "lonely", false);
		update_led_flag(&gDatto_net_ubus_conn.ctx, "orphan", true);
	} else if (gDatto_net_state.inet_test.upstream_state != DATTO_NET_UPSTREAM_LONELY_ORPHAN_STATE) {
		update_led_flag(&gDatto_net_ubus_conn.ctx, "lonely", false);
		update_led_flag(&gDatto_net_ubus_conn.ctx, "orphan", false);
	}

	/* We just got out of orphan, make sure we think we're a repeater */
	if (gWifi_settings.orphan_connect_bssid[0] && !new_settings.orphan_connect_bssid[0]) {
		gDatto_net_state.inet_test.test_failures = 0;
		complete_inet_test(DATTO_NET_UPSTREAM_MESH_STATE);
	}

	/* Pull in the remaining mesh settings (key pulled from a radio) */
	/* We only have 1 batman control interface, so always pass in 0 as an arg */
	ng_uci_data_get_val(new_settings.mesh.protocol, sizeof(new_settings.mesh.protocol), uci_addr_batman_protocol, 0);
	ng_uci_data_get_val_int(&new_settings.mesh.batman.hop_penalty, uci_addr_batman_hop_penalty, 0);
	ng_uci_data_get_val_int(&new_settings.mesh.batman.gw_stickiness, uci_addr_batman_gw_stickiness, 0);
	ng_uci_data_get_val_bool(new_settings.mesh.batman.bridge_loop_avoidance, uci_addr_batman_bridge_loop_avoidance, 0);

	/* reconcile per-band vs. per-ssid settings */
	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		int radio_idx = 0;
		int base_band = 0;

		/* Find a base radio that is not a scanning radio */
		for (radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
			base_band = wifid_find_band(radio_idx);

			if (base_band != BAND_SCANNING)
				break;
		}

		if (!IS_VALID_ARRAY_INDEX(base_band, BAND_MAX)) {
			debug_msg_warn("Failed to find 2.4Ghz band");
			break;
		}

		bool change_found = false;

		for (radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
			int cur_band = wifid_find_band(radio_idx);

			/* If there are no more radios, we're done here */
			if (!IS_VALID_ARRAY_INDEX(cur_band, BAND_MAX))
				break;

			/* Skip the band we are testing against */
			if (cur_band == base_band)
				continue;

			/* No radio configuration for scanning radios */
			if (cur_band == BAND_SCANNING)
				continue;

			/* Per-band enables already handled, check SSID names */
			if (strcmp(new_settings.ssid[ssid_idx].band[base_band].ssid, new_settings.ssid[ssid_idx].band[cur_band].ssid))
				change_found = true;
		}

		/* If we got through all valid radios without any differences, we don't have per-band
		 * settings. This means we should copy the SSID name to the overall SSID, and clear out
		 * the per-band part of the struct, since these aren't actually per-band settings.
		 */
		if (!change_found) {
			snprintf(new_settings.ssid[ssid_idx].ssid, sizeof(new_settings.ssid[ssid_idx].ssid), "%s", new_settings.ssid[ssid_idx].band[base_band].ssid);
			memset(new_settings.ssid[ssid_idx].band, 0, sizeof(new_settings.ssid[ssid_idx].band));
		}
	}

	/* Delete old vlan ifaces */
	for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
		if (!VALID_VLAN_TAG(gWifi_settings.ssid[ssid_idx].vlan_tag) || (gWifi_settings.ssid[ssid_idx].vlan_tag == new_settings.ssid[ssid_idx].vlan_tag))
			continue;

		for (int ifnum_idx = 0; ifnum_idx < WIRED_MAX; ++ifnum_idx) {
			char vlan_if[IFNAMSIZ] = {0};

			snprintf(vlan_if, sizeof(vlan_if), "eth%d.%d", ifnum_idx, gWifi_settings.ssid[ssid_idx].vlan_tag);
			ng_rtnl_iface_destroy(vlan_if);
		}
	}

	int temp_client_ssid = 0;

	ng_uci_data_get_val_int(&temp_client_ssid, "%s", uci_addr_datto_net_wired_client_bridge);

	if (CHECK_RANGE(temp_client_ssid, 1, SSID_MAX))
		new_settings.wired_client_ssid = temp_client_ssid;

	ng_uci_data_get_val_bool(new_settings.disable_wired_client, "%s", uci_addr_datto_net_disable_wired_client);

	new_settings.presence_enable = (ng_uci_check_val("1", "%s", uci_addr_prequestd_enable) == 1);
	ng_uci_data_get_val_int(&new_settings.presence_period, "%s", uci_addr_prequestd_interval);

	new_settings.recover_config_errors = 1;
	ng_uci_data_get_val_int(&new_settings.recover_config_errors, "%s", uci_addr_recover_config);

	wifid_write_ctl_variant(&new_settings, fresh_start);

	/* TODO: this is prior to the memcpy so it can see changes between the new settings and the
	 * previous settings so we can do cleanup of outdated bridges. We may want to add a dedicated
	 * cleanup function instead of doing cleanup and creation in the wifid_apply_bridges function
	 */
	wifid_apply_bridges(&new_settings);

	memcpy(&gWifi_settings, &new_settings, sizeof(gWifi_settings));

	/*
	 * The acl_vlist head was copied over to the new settings structure at the start so that
	 * we could take advantage of the update functionality to detect changes to the list.
	 * This means that we don't need to do anything here for it.
	 */

	wifid_apply_neighbors(&gDatto_net_ubus_conn.ctx);

	/* start a watchdog timer to make sure u80211d actually runs the scan */
	wifi_scan_restart_watchdog_timer();

	// Disable firewall rules for SSIDs that are bridged to LAN or are VLAN tagged
	set_firewall_forwarding_rules(gDatto_net_state.inet_test.system_inet_interface, gDatto_net_state.inet_test.upstream_state);

	wifid_modify_presence_periodic_checkin();

	wifid_run_orphand();

	return 0;
}
