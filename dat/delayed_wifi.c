/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "main.h"
#include "settings.h"
#include "wifi/lldp.h"
#include "wifi/settings/delayed_wifi.h"
#include "wifi/settings/reload_config.h"
#include "wifi/settings/ssid.h"
#include "wifi/settings/uci_addrs.h"
#include "wired/online.h"

#include <libomcommon/common.h>
#include <libomcommon/debug_msg.h>
#include <libomcommon/file.h>
#include <libomcommon/led.h>
#include <libomcommon/package.h>
#include <libomcommon/uci.h>

#include <libfwcore/platform/wireless.h>

void wifid_cancel_delayed_wifi(void)
{
	/* Nothing pending, silently say we did it */
	if (!gWifi_state.delayed_wifi_file[0])
		return;

	debug_msg_notice("Aborting delayed wifi settings from file %s", gWifi_state.delayed_wifi_file);

	uloop_timeout_cancel(&gWifi_state.delayed_wifi_timer);
	unlink(gWifi_state.delayed_wifi_file);
	gWifi_state.delayed_wifi_file[0] = '\0';

	update_led_flag(&gDatto_net_ubus_conn.ctx, "config", false);
}

static void wifi_delayed_wifi_cb(struct uloop_timeout OM_UNUSED(*timer))
{
	debug_msg_notice("Applying delayed wifi settings from file %s", gWifi_state.delayed_wifi_file);
	ng_uci_batch_apply(gWifi_state.delayed_wifi_file, true);

	// Delay 60s before checking in after ending delayed wifi to allow for all radios to come up
	if (gWifi_state.delayed_wifi_file[0])
		cloud_checkin(&gDatto_net_ubus_conn.ctx, "normal", 60);

	unlink(gWifi_state.delayed_wifi_file);
	gWifi_state.delayed_wifi_file[0] = '\0';

	wifi_restore_config_enabled_interfaces(false);

	system("reload_config");
	system("/etc/init.d/dnsmasq reload");

	update_led_flag(&gDatto_net_ubus_conn.ctx, "config", false);

	/* Revert ourselves back to the initial state for inet test, to allow the mesh to go through a
	 * full reload cycle
	 */
	gDatto_net_state.inet_test.test_result = true;
	complete_inet_test(DATTO_NET_UPSTREAM_NONE);
}

// UBUS method to bypass the delayed wifi wait period (DELAYED_WIFI_TIME)
int ubus_wifi_end_delayed_wifi(struct ubus_context OM_UNUSED(*ctx), struct ubus_object OM_UNUSED(*obj), struct ubus_request_data OM_UNUSED(*req), const char OM_UNUSED(*method), struct blob_attr OM_UNUSED(*msg))
{
	debug_msg_info("bypassing delayed wifi wait period");
	uloop_timeout_cancel(&gWifi_state.delayed_wifi_timer);
	wifi_delayed_wifi_cb(NULL);

	return 0;
}

void parse_config_event_delayed_wifi(bool success)
{
	/* We don't have a "new" delayed wifi config file, there's nothing to do here, exit silently */
	if (!gWifi_state.new_delayed_wifi_file[0])
		return;

	if (success) {
		bool changed = true;

		if (gWifi_state.delayed_wifi_file[0]) {
			char diff_cmd[512] = {0};

			snprintf(diff_cmd, sizeof(diff_cmd), "diff %s %s", gWifi_state.delayed_wifi_file, gWifi_state.new_delayed_wifi_file);

			int ret = system(diff_cmd);

			if (ret == -1) {
				/* If we failed to diff for some reason, assume they're different and delay more */
				debug_msg_warn("diff command '%s' failed, errno = %d:%s", diff_cmd, errno, strerror(errno));
			} else {
				/* A non-zero return code from diff means the files differed, zero the same. */
				changed = WEXITSTATUS(ret);
			}
		}

		if (changed) {
			/* Kill the old delayed wifi */
			wifid_cancel_delayed_wifi();

			/* Replace it with the new one */
			snprintf(gWifi_state.delayed_wifi_file, sizeof(gWifi_state.delayed_wifi_file), "%s", gWifi_state.new_delayed_wifi_file);
			gWifi_state.new_delayed_wifi_file[0] = '\0';

			/* Start the timer */
			gWifi_state.delayed_wifi_timer.cb = wifi_delayed_wifi_cb;

			uloop_timeout_set(&gWifi_state.delayed_wifi_timer, DELAYED_WIFI_TIME);

			debug_msg_notice("Starting timer for delayed wifi settings with file %s", gWifi_state.delayed_wifi_file);
			update_led_flag(&gDatto_net_ubus_conn.ctx, "config", true);
			return;
		}
	}

	debug_msg_info("No changes in delayed wifi settings for file %s, deleting it", gWifi_state.new_delayed_wifi_file);

	/* The existing delayed wifi config is fine, go with that */
	unlink(gWifi_state.new_delayed_wifi_file);
	gWifi_state.new_delayed_wifi_file[0] = '\0';
}

static bool wifid_need_delay(struct wifi_settings *parsed_settings)
{
	NULL_ASSERT(true, parsed_settings);

	bool mesh_enabled = false;
	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx)
		mesh_enabled |= parsed_settings->radio[radio_idx].mesh_enable;

	/* If the mesh is disabled, don't delay */
	if (!mesh_enabled)
		return false;

	/* If we have a radio override from somewhere, don't delay, apply
	 * the settings now
	 */
	if (parsed_settings->radio_override[0])
		return false;

	/* If we're coming out of orphan, we don't need to have delayed wifi */
	if (!parsed_settings->orphan_connect_bssid[0] && gWifi_settings.orphan_connect_bssid[0])
		return false;

	/* Check mesh settings for changes */
		/* mesh key */
		/* mesh protocol */
	if (strncmp(parsed_settings->mesh.key, gWifi_settings.mesh.key, sizeof(parsed_settings->mesh.key)))
		return true;

	if (strncmp(parsed_settings->mesh.protocol, gWifi_settings.mesh.protocol, sizeof(parsed_settings->mesh.protocol)))
		return true;

	/* Check batman settings for changes */
	if (parsed_settings->mesh.batman.hop_penalty != gWifi_settings.mesh.batman.hop_penalty)
		return true;

	if (parsed_settings->mesh.batman.gw_stickiness != gWifi_settings.mesh.batman.gw_stickiness)
		return true;

	if (parsed_settings->mesh.batman.bridge_loop_avoidance != gWifi_settings.mesh.batman.bridge_loop_avoidance)
		return true;

	/* Check country & indoor/outdoor changes */
	if (parsed_settings->reg_outdoor != gWifi_settings.reg_outdoor)
		return true;

	if (strncmp(parsed_settings->reg_country, gWifi_settings.reg_country, sizeof(parsed_settings->reg_country)))
		return true;

	/* Check antenna type changes */
	if (parsed_settings->antenna_type != gWifi_settings.antenna_type)
		return true;

	/* Check radio enable, channel, and mode for changes */
	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		/* Skip scanning radios */
		if (platform_wireless_radio_is_scanning(radio_idx))
			continue;

		if (parsed_settings->radio[radio_idx].enable != gWifi_settings.radio[radio_idx].enable)
			return true;

		if (parsed_settings->radio[radio_idx].channel != gWifi_settings.radio[radio_idx].channel)
			return true;

		if (strncmp(parsed_settings->radio[radio_idx].mode, gWifi_settings.radio[radio_idx].mode, sizeof(parsed_settings->radio[radio_idx].mode)))
			return true;

		if (parsed_settings->radio[radio_idx].mesh_enable != gWifi_settings.radio[radio_idx].mesh_enable)
			return true;
	}

	return false;
}

int wifid_write_delayed_wifi_config(struct wifi_settings *parsed_settings, char *delayed_wifi_file)
{
	NULL_ASSERT2(-1, parsed_settings, delayed_wifi_file);

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;
	char channel_str[8] = {0};
	bool lldp_done = wifi_lldp_negotiation_complete();

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		/* Skip scanning radios */
		if (platform_wireless_radio_is_scanning(radio_idx))
			continue;

		/* Set radio enable, channel, and mode */
		ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->radio[radio_idx].enable, uci_addr_radio_enable, radio_idx);
		ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->radio[radio_idx].channel, uci_addr_radio_channel, radio_idx);
		ng_uci_batch_set_fmt_string(delayed_wifi_file, parsed_settings->radio[radio_idx].mode, uci_addr_radio_htmode, radio_idx);

		/* Set reg country */
		ng_uci_batch_set_fmt_string(delayed_wifi_file, parsed_settings->reg_country, uci_addr_radio_country, radio_idx);

		/* Immediately set country into scanning radio daemon */
		ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->reg_country, "%s", uci_addr_u80211d_country);

		/* We need to wait until we've changed channels to change our enable value, so that
		 * if we're starting on an "invalid" channel for a geo, we don't enable the mesh
		 * and AP interfaces on that "invalid" channel.  For example, if we are in Canada
		 * and outdoor, we can't operate on the "default" 5GHz channel of 44.
		 */
		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
			int enable = wifid_is_ssid_band_enabled(parsed_settings, ssid_idx, radio_idx);

			/* Save the parsed enable flag to the apX_Y config_enable option. This will be read
			 * back in reload_config
			 */
			ng_uci_batch_set_fmt_int(delayed_wifi_file, enable, uci_addr_ap_config_enable, radio_idx, ssid_idx + 1);

			ng_uci_batch_set_fmt_int(delayed_wifi_file, lldp_done ? enable : false, uci_addr_ap_enable, radio_idx, ssid_idx + 1);
			ng_uci_batch_set_fmt_int(delayed_wifi_file, ssid_idx, uci_addr_ap_ssidno, radio_idx, ssid_idx + 1);
		}

		if (parsed_settings->radio[radio_idx].enable && parsed_settings->radio[radio_idx].mesh_enable) {
			ng_uci_batch_set_fmt_int(delayed_wifi_file, true, uci_addr_mesh_config_enable, radio_idx);
			ng_uci_batch_set_fmt_string(delayed_wifi_file, "interface", DATTO_NET_UCI_NETWORK_MESH, radio_idx);
			ng_uci_batch_set_fmt_string(delayed_wifi_file, "1544", uci_addr_network_mesh_mtu, radio_idx);
			ng_uci_batch_set_fmt_string(delayed_wifi_file, "batadv_hardif", uci_addr_network_mesh_proto, radio_idx);
			ng_uci_batch_set_fmt_string(delayed_wifi_file, "bat0", uci_addr_network_mesh_master, radio_idx);
		} else {
			ng_uci_batch_set_fmt_int(delayed_wifi_file, false, uci_addr_mesh_config_enable, radio_idx);
			ng_uci_batch_del_fmt(delayed_wifi_file, DATTO_NET_UCI_NETWORK_MESH, radio_idx);
		}

		/* TODO: There should probably be a list of reasons the mesh might be disabled and then
		 * uci_addr_mesh_enable is set based off of that
		 */

		/* Set mesh enable and key */
		if (wifid_channel_is_dfs(parsed_settings->radio[radio_idx].channel, parsed_settings->radio[radio_idx].mode)) {
			debug_msg_warn("Disabling mesh%d due to DFS radio channel", radio_idx);
			ng_uci_batch_set_fmt_int(delayed_wifi_file, 0, uci_addr_mesh_enable, radio_idx);
		} else if (!parsed_settings->radio[radio_idx].enable) {
			debug_msg_info("Disabling mesh%d due to radio disable", radio_idx);
			ng_uci_batch_set_fmt_int(delayed_wifi_file, 0, uci_addr_mesh_enable, radio_idx);
		} else {
			debug_msg_debug("mesh%d set to %d", radio_idx, parsed_settings->radio[radio_idx].mesh_enable);
			ng_uci_batch_set_fmt_int(delayed_wifi_file, lldp_done ? parsed_settings->radio[radio_idx].mesh_enable : false, uci_addr_mesh_enable, radio_idx);
		}
		ng_uci_batch_set_fmt_string(delayed_wifi_file, parsed_settings->mesh.key, uci_addr_mesh_key, radio_idx);

		/* Set DFS enable and chanlist */
		if (wifid_radio_has_dfs(radio_idx)) {
			ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->dfs.enable, uci_addr_radio_dfs_enable, radio_idx);
			ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->dfs.channel_count, uci_addr_radio_chanlist_count, radio_idx);

			/* Delete the old list */
			file_append_string_fmt(delayed_wifi_file, "delete wireless.radio%d.channels\n", radio_idx);

			for (unsigned int channel_idx = 0; channel_idx < parsed_settings->dfs.channel_count; ++channel_idx) {
				snprintf(channel_str, sizeof(channel_str), "%d", parsed_settings->dfs.channel[channel_idx]);
				ng_uci_batch_fmt_list(delayed_wifi_file, true, channel_str, uci_addr_radio_chanlist, radio_idx);
			}
		}
	}

	/* Set outdoor and antenna type */
	ng_uci_batch_set_int(delayed_wifi_file, parsed_settings->reg_outdoor, uci_addr_outdoor);
	ng_uci_batch_set_int(delayed_wifi_file, parsed_settings->antenna_type, uci_addr_antenna);

	/* Set batman settings: protocol, hop_penalty, gw_stickiness, bridge_loop_avoidance, etc... */
	ng_uci_batch_set_fmt_string(delayed_wifi_file, parsed_settings->mesh.protocol, uci_addr_batman_protocol, 0);
	ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->mesh.batman.hop_penalty, uci_addr_batman_hop_penalty, 0);
	ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->mesh.batman.gw_stickiness, uci_addr_batman_gw_stickiness, 0);
	ng_uci_batch_set_fmt_int(delayed_wifi_file, parsed_settings->mesh.batman.bridge_loop_avoidance, uci_addr_batman_bridge_loop_avoidance, 0);

	bool need_delay = wifid_need_delay(parsed_settings);

	// if there was a setting change and delayed wifi is enabled, run the delay
	if (need_delay && parsed_settings->delayed_wifi) {
		snprintf(gWifi_state.new_delayed_wifi_file, sizeof(gWifi_state.new_delayed_wifi_file), "%s", delayed_wifi_file);
		return 0;
	}

	// at this point, just apply the settings
	int ret = ng_uci_batch_apply(delayed_wifi_file, false) ? -1 : 0;

	unlink(delayed_wifi_file);

	/* We're no longer delaying, clean up any old pending delayed wifi settings */
	wifid_cancel_delayed_wifi();

	return ret;
}
