/***
 *
 * Copyright (C) 2021-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "main.h"
#include "wifi/bridge.h"
#include "wifi/settings/hostapd_ft_mgmt.h"

#include <libomcommon/blobmsg.h>
#include <libomcommon/common.h>
#include <libomcommon/debug_msg.h>

#include <libfwcore/platform/wireless.h>

#include <net/if.h>

void wifi_flush_hapd_instance_list(struct wifi_state *state)
{
	NULL_ASSERT(VOID_RETURN_VALUE, state);

	if (!state->hapd_instances.next)
		return;

	struct hapd_instance *cur_instance = NULL;
	struct hapd_instance *tmp_ptr_storage = NULL;

	list_for_each_entry_safe(cur_instance, tmp_ptr_storage, &state->hapd_instances, list) {
		list_del(&cur_instance->list);
		free(cur_instance);    /* Explicitly set to NULL on next line */
		cur_instance = NULL;
	}
}

void wifi_remove_hapd_instance_from_list(char *ubus_path)
{
	NULL_ASSERT(VOID_RETURN_VALUE, ubus_path);

	if (!gWifi_state.hapd_instances.next)
		return;

	struct hapd_instance *cur_instance = NULL, *tmp_ptr_storage = NULL;

	/* Walk list of hapd instances, find the matching ubus path, delete the instance from list */
	list_for_each_entry_safe(cur_instance, tmp_ptr_storage, &gWifi_state.hapd_instances, list) {
		if (strncmp(cur_instance->ubus_path, ubus_path, sizeof(cur_instance->ubus_path)))
			continue;

		list_del(&cur_instance->list);
		free(cur_instance);    /* Explicitly set to NULL on next line */
		cur_instance = NULL;

		break;
	}
}

void wifi_add_hapd_instance_to_list(char *ubus_path, int ssid_idx)
{
	NULL_ASSERT(VOID_RETURN_VALUE, ubus_path);

	uint32_t ubus_id = 0;

	if (ubus_lookup_id(&gDatto_net_ubus_conn.ctx, ubus_path, &ubus_id) != UBUS_STATUS_OK) {
		debug_msg_warn("Unable to lookup UBUS id for '%s'", ubus_path);
		return;
	}

	/* Walk the list of hapd instances to see if this path already exists */
	if (gWifi_state.hapd_instances.next) {
		struct hapd_instance *cur_instance = NULL;

		list_for_each_entry(cur_instance, &gWifi_state.hapd_instances, list) {
			if (strncmp(cur_instance->ubus_path, ubus_path, sizeof(cur_instance->ubus_path)))
				continue;

			/* If this path is already being tracked, update the UBUS id and exit */
			cur_instance->ubus_id = ubus_id;

			return;
		}
	}

	/* If the passed ssid_idx is not valid, such as -1, attempt to recover
	 * the ssid_idx from the UBUS path.
	 */
	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX)) {
		int radio = 0;

		if (sscanf(ubus_path, "hostapd.ap%i_%i", &radio, &ssid_idx) != 2) {
			debug_msg_err("Failed to pull radio_idx and ssid_idx from the UBUS path for %s", ubus_path);
			return;
		}

		/* Decrement explicitly prior to IS_VALID_ARRAY_INDEX bounds check.
		 * Macro expansion may result in a double decrement of variable
		 */
		--ssid_idx;

		/* Assert that the recovered ssid_idx is valid */
		if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX)) {
			debug_msg_err("Failed to pull a valid ssid_idx from the UBUS path for %s", ubus_path);
			return;
		}
	}

	struct hapd_instance *new_instance = calloc(1, sizeof(struct hapd_instance));

	if (!new_instance) {
		debug_msg_err("Failed to alloc memory for new hostapd UBUS instance. UBUS path: %s", ubus_path);
		return;
	}

	snprintf(new_instance->ubus_path, sizeof(new_instance->ubus_path), "%s", ubus_path);
	new_instance->ubus_id = ubus_id;
	new_instance->ssid_idx = ssid_idx;

	if (!gWifi_state.hapd_instances.next)
		INIT_LIST_HEAD(&gWifi_state.hapd_instances);

	list_add_tail(&new_instance->list, &gWifi_state.hapd_instances);
}

void wifi_enumerate_hapd_instances_add_to_list(void)
{
	char hapd_path[HAPD_UBUS_NAME_MAX] = {0};
	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;
	int ret;

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		if (platform_wireless_radio_is_scanning(radio_idx))
			continue;

		for (int ssid_idx = 0; ssid_idx < SSID_MAX; ++ssid_idx) {
			ret = snprintf(hapd_path, sizeof(hapd_path), "hostapd.ap%d_%d", radio_idx, ssid_idx + 1);
			if (ret >= (int)sizeof(hapd_path))
				continue;

			wifi_add_hapd_instance_to_list(hapd_path, ssid_idx);
		}
	}
}

static void call_hapd_update_ft_auth_bridge(struct hapd_instance *instance, char *bridge_name)
{
	NULL_ASSERT2(VOID_RETURN_VALUE, instance, bridge_name);

	struct blob_buf bridge_name_buf = {0};    /* Zeroed out in blob_buf_init() below */

	if (blob_buf_init(&bridge_name_buf, 0)) {
		debug_msg_warn("Unable to initialize buffer to update ft_auth_bridge to '%s' for '%s'", bridge_name, instance->ubus_path);
		return;
	}

	if (blobmsg_add_string(&bridge_name_buf, "bridge", bridge_name)) {
		debug_msg_warn("Unable to add '%s' to the update ft_auth_bridge UBUS request for '%s'", bridge_name, instance->ubus_path);
		blob_buf_free(&bridge_name_buf);
		return;
	}

	struct ubus_request req = {0};

	/* We don't care about the result, so it's OK for the req to leave scope on exit. */
	if (ubus_invoke_async(&gDatto_net_ubus_conn.ctx, instance->ubus_id, "update_ft_auth_bridge", bridge_name_buf.head, &req) != UBUS_STATUS_OK)
		debug_msg_warn("Unable to update ft_auth_bridge to '%s' for '%s'", bridge_name, instance->ubus_path);

	blob_buf_free(&bridge_name_buf);
}

void wifi_update_hapd_ft_auth_bridges(struct wifi_settings *settings)
{
	NULL_ASSERT(VOID_RETURN_VALUE, settings);

	if (!gWifi_state.hapd_instances.next)
		return;

	struct hapd_instance *cur_instance = NULL;
	char bridge_name[IFNAMSIZ] = {0};

	/* Call the update_ft_auth_bridge UBUS method for hostapd for each hostapd UBUS instance.
	 * If the bridge is not different, hostapd will not re-init the bridge it uses.
	 * Because of this, we don't need to track which bridge is being used.
	 */
	list_for_each_entry(cur_instance, &gWifi_state.hapd_instances, list) {
		/* If 802.11r is not enabled for this SSID, don't update the ft_auth_bridge for this hapd
		 * instance. When 802.11r is re-enabled, the bridge will be updated during the parse_config
		 * process.
		 */
		if (!settings->ssid[cur_instance->ssid_idx].roaming_domain[0] || !settings->ssid[cur_instance->ssid_idx].roaming_key[0])
			continue;

		determine_dest_ssid_bridge(settings, bridge_name, sizeof(bridge_name), cur_instance->ssid_idx);

		/* If we didn't determine which bridge this AP iface should be in, don't update hostapd. */
		if (!bridge_name[0])
			continue;

		call_hapd_update_ft_auth_bridge(cur_instance, bridge_name);

		bridge_name[0] = '\0';
	}
}

void wifi_update_hapd_ft_auth_bridges_delayed(struct uloop_timeout OM_UNUSED(*timer))
{
	wifi_update_hapd_ft_auth_bridges(&gWifi_settings);
}

void wifi_dump_hapd_ft_auth_bridges_state(struct blob_buf *dump_blobmsg)
{
	NULL_ASSERT(VOID_RETURN_VALUE, dump_blobmsg);

	void *hapd_instances_top_level_cookie = blobmsg_open_array(dump_blobmsg, "hostapd_instances");

	if (!hapd_instances_top_level_cookie) {
		debug_msg_warn("Unable to add 'hostapd_instances' to state dump");
		return;
	}

	if (!gWifi_state.hapd_instances.next) {
		blobmsg_close_array(dump_blobmsg, hapd_instances_top_level_cookie);
		return;
	}

	struct hapd_instance *cur_instance = NULL;

	list_for_each_entry(cur_instance, &gWifi_state.hapd_instances, list) {
		void *hapd_instance_table_cookie = blobmsg_open_table(dump_blobmsg, "");

		if (!hapd_instance_table_cookie) {
			debug_msg_warn("Unable to open table for hostapd instance '%s' for state dump", cur_instance->ubus_path);
			continue;
		}

		BLOBMSG_ADD_CALL_WARN(string, dump_blobmsg, "ubus_path", cur_instance->ubus_path, "Unable to add 'ubus_path' member to hostapd_instances dump");
		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "ubus_id", cur_instance->ubus_id, "Unable to add 'ubus_id' member to hostapd_instances dump");
		BLOBMSG_ADD_CALL_WARN(u32, dump_blobmsg, "ssid_idx", cur_instance->ssid_idx, "Unable to add 'ssid_idx' member to hostapd_instances dump");

		blobmsg_close_table(dump_blobmsg, hapd_instance_table_cookie);
		hapd_instance_table_cookie = NULL;
	}

	blobmsg_close_array(dump_blobmsg, hapd_instances_top_level_cookie);
	hapd_instances_top_level_cookie = NULL;
}
