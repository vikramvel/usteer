/***
 *
 * Copyright (C) 2022-2023 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#include "settings.h"
#include "wifi/bridge.h"
#include "wifi/settings/parse_config.h"
#include "wifi/settings/ssid.h"
#include "wifi/settings/uci_addrs.h"
#include "wifi/settings/write_config.h"

#include <arpa/inet.h>

#include <libomcommon/common.h>
#include <libomcommon/debug_msg.h>
#include <libomcommon/file.h>
#include <libomcommon/str_util.h>
#include <libomcommon/uci.h>

#include <libfwcore/platform/wireless.h>

/* Function: wifid_is_ssid_band_enabled
 * ----------------------------
 * This will find the band by radio_idx and search if an ssid band is enabled.
 *
 * This will be the "enable" for the interface, but not if it should be broadcasting.
 *
 * NOTE: The function caller must verify pointers and bounds to function inputs.
 *
 * Inputs:	struct wifi_settings *const settings - This is the settings struct to look through
 *			int ssid_idx - index into the ssid member of the settings struct
 *			int radio_idx - index passed to wifid_find_band
 *
 * Output:	bool - True if band is enabled, False if band is not enabled
 */
bool wifid_is_ssid_band_enabled(struct wifi_settings *const settings, int ssid_idx, int radio_idx)
{
	int enable = !!settings->ssid[ssid_idx].enable;
	int band = wifid_find_band(radio_idx);

	if (!IS_VALID_ARRAY_INDEX(band, BAND_MAX))
		return false;

	if (!settings->radio[radio_idx].enable)
		return false;

	/* We turn on the AP iface if wifi scheduling is on, and use the "start_disabled" flag to
	 * prevent it from broadcasting. This resolves issues where enabling/disabling an SSID can
	 * cause other SSIDs/ifaces to briefly go down. This "overrides" the enable flag for the SSID
	 * as a whole. The cloud will send down "disabled" for that if we should stop broadcasting.
	 */
	if (settings->ssid[ssid_idx].wifi_scheduling)
		return true;

	if (!enable)
		return false;

	for (int band_check = 0; band_check < BAND_MAX; ++band_check) {
		/* If any of the bands have a valid SSID name, use the enable flag from OUR band */
		if (settings->ssid[ssid_idx].band[band_check].ssid[0]) {
			enable = settings->ssid[ssid_idx].band[band].enable;
			break;
		}
	}

	return enable;
}

/* Function: compare_option_name()
 *
 * A small wrapper around strncmp() that will compare UCI list option values against an interface
 * name. The interface name string must be passed as a void *, the UCI library expects this format
 * when calling this function. This function is used in a ng_uci_list_foreach() call that searches
 * for matching interface names in a DHCP UCI interface and notinterface list.
 *
 * Inputs:  char *option_name - This is the interface name in the UCI list
 *          void *iface_name_to_check - This is the interface name to look for.
 *
 * Outputs: int - 0 for no match, -1 for match.
 */
static int compare_option_name(char *option_name, void *iface_name_to_check)
{
	/* If the pointers are null, return no match */
	NULL_ASSERT2(0, option_name, iface_name_to_check);

	return (strcmp(option_name, iface_name_to_check) != 0) ? 0 : -1;
}

static void wifid_write_ssid_dns_intercept_config(struct wifi_settings *parsed_settings, int ssid_idx)
{
	NULL_ASSERT(VOID_RETURN_VALUE, parsed_settings);

	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX)) {
		debug_msg_err("Passed SSID index is out of range, passed %d vs max %d", ssid_idx, SSID_MAX);
		return;
	}

	char ssid_str[32] = {0};
	char ssid_dns_str[32] = {0};
	char ssid_br_str[32] = {0};
	char ssid_vlan_str[32] = {0};

	snprintf(ssid_str, sizeof(ssid_str), "ssid%d", ssid_idx + 1);
	snprintf(ssid_dns_str, sizeof(ssid_dns_str), "ssid%d_dns", ssid_idx + 1);
	snprintf(ssid_br_str, sizeof(ssid_br_str), "br-ssid%d", ssid_idx + 1);
	snprintf(ssid_vlan_str, sizeof(ssid_vlan_str), "br-ssid%d_vlan", ssid_idx + 1);

	/* We have per-ssid settings, first, remove our interface from the "main" DNS interface list */
	ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_br_str, DATTO_NET_UCI_DHCP ".lan_dns.interface");
	ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_vlan_str, DATTO_NET_UCI_DHCP ".lan_dns.interface");

	/* Add it to the notinterface list on the "main" DNS interface */
	/* If this list item does not exist, add it. If it does exist, move along */
	if (ng_uci_list_foreach(DATTO_NET_UCI_DHCP ".lan_dns.notinterface", compare_option_name, ssid_br_str) == 0)
		ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_br_str, DATTO_NET_UCI_DHCP ".lan_dns.notinterface");

	if (ng_uci_list_foreach(DATTO_NET_UCI_DHCP ".lan_dns.notinterface", compare_option_name, ssid_vlan_str) == 0)
		ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_vlan_str, DATTO_NET_UCI_DHCP ".lan_dns.notinterface");

	/* Add the DHCP pool to the per-ssid DNS instance unless relayed */
	if (!parsed_settings->ssid[ssid_idx].dhcp.relay[0])
		ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_dns_str, DATTO_NET_UCI_DHCP_SSID ".instance", ssid_idx + 1);

	/* Create our per-ssid DNS instance */
	ng_uci_set_string(gDatto_net_state.uci_ctx, "dnsmasq", DATTO_NET_UCI_DHCP_SSID_DNS, ssid_idx + 1);

	/* NOTE: This is the correct spelling for localize, I promise */
	ng_uci_set_int(gDatto_net_state.uci_ctx, 1, DATTO_NET_UCI_DHCP_SSID_DNS ".localise_queries", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 1, DATTO_NET_UCI_DHCP_SSID_DNS ".rebind_localhost", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 0, DATTO_NET_UCI_DHCP_SSID_DNS ".readethers", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 0, DATTO_NET_UCI_DHCP_SSID_DNS ".nonwildcard", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 1, DATTO_NET_UCI_DHCP_SSID_DNS ".bindinterface", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 1, DATTO_NET_UCI_DHCP_SSID_DNS ".expandhosts", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 0, DATTO_NET_UCI_DHCP_SSID_DNS ".boguspriv", ssid_idx + 1);

	ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_str, DATTO_NET_UCI_DHCP_SSID_DNS ".domain", ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, 1, DATTO_NET_UCI_DHCP_SSID_DNS ".domainneeded", ssid_idx + 1);

	/*
	 * DNS cache enabled:
	 *		we want to use its default size, so we shouldn't set the cachesize option.
	 * DNS cache disabled:
	 *		we should set the cachesize option to 0, which tells dnsmasq to disable it.
	 */
	if (parsed_settings->ssid[ssid_idx].dns_cache_enable)
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_SSID_DNS ".cachesize", ssid_idx + 1);
	else
		ng_uci_set_int(gDatto_net_state.uci_ctx, 0, DATTO_NET_UCI_DHCP_SSID_DNS ".cachesize", ssid_idx + 1);

	char tmp_buf[64] = {0};

	/* NOTE: Fixes configurations in the case of sysupgrades from older builds */
	ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_SSID_DNS ".local", ssid_idx + 1);

	snprintf(tmp_buf, sizeof(tmp_buf), "/tmp/dhcp_ssid%d.leases", ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, tmp_buf, DATTO_NET_UCI_DHCP_SSID_DNS ".leasefile", ssid_idx + 1);

	snprintf(tmp_buf, sizeof(tmp_buf), "/tmp/resolv.conf.d/resolv.conf.ssid%d", ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, tmp_buf, DATTO_NET_UCI_DHCP_SSID_DNS ".resolvfile", ssid_idx + 1);

	ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_dhcp_ssid_dns_server, ssid_idx + 1);

	for (int d = 0; (d < DNS_MAX) && (parsed_settings->ssid[ssid_idx].dns_server[d][0]); ++d)
		ng_uci_add_list(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dns_server[d], uci_addr_dhcp_ssid_dns_server, ssid_idx + 1);

	/* If there are no override servers, then add "localhost".  This is so that dnsmasq
	 * will see the DNS requests (and forward them), so that it can update the ipsets
	 * for walled garden support.
	 */
	if (!parsed_settings->ssid[ssid_idx].dns_server[0][0])
		ng_uci_add_list(gDatto_net_state.uci_ctx, "127.0.0.1", uci_addr_dhcp_ssid_dns_server, ssid_idx + 1);

	/* Firewall rules for DNS intercept set up in firewall.d */
	if (parsed_settings->ssid[ssid_idx].bridge_to_lan) {
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_dhcp_ssid_dns_interface, ssid_idx + 1);
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
		ng_uci_set_int(gDatto_net_state.uci_ctx, DNS_INTERCEPT_BTL_BASE_PORT_NO + ssid_idx + 1, uci_addr_dhcp_ssid_dns_port, ssid_idx + 1);
	} else {
		/* Add the ssid bridge into the "main" DNS instance for the SSID */
		ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_br_str, uci_addr_dhcp_ssid_dns_interface, ssid_idx + 1);
		ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_br_str, uci_addr_dhcp_ssid_dns_interface, ssid_idx + 1);

		/* Add the SSID VLAN bridge into the "main" DNS instance for the SSID */
		ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_vlan_str, uci_addr_dhcp_ssid_dns_interface, ssid_idx + 1);
		ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_vlan_str, uci_addr_dhcp_ssid_dns_interface, ssid_idx + 1);

		if (gDatto_net_state.current_wired_uplink[0]) {
			ng_uci_del_list(gDatto_net_state.uci_ctx, gDatto_net_state.current_wired_uplink, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
			ng_uci_add_list(gDatto_net_state.uci_ctx, gDatto_net_state.current_wired_uplink, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
		}

		ng_uci_del_list(gDatto_net_state.uci_ctx, "br-mesh_gw", uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "br-mesh_gw", uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);

		ng_uci_del_list(gDatto_net_state.uci_ctx, "br-mesh_rp", uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "br-mesh_rp", uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);

		ng_uci_del_list(gDatto_net_state.uci_ctx, "lo", uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
		ng_uci_add_list(gDatto_net_state.uci_ctx, "lo", uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);

		char tmp_vlan_buf[64] = {0};

		for (int ssid_idx_add = 0; ssid_idx_add < SSID_MAX; ++ssid_idx_add) {
			snprintf(tmp_buf, sizeof(tmp_buf), "br-ssid%d", ssid_idx_add + 1);
			ng_uci_del_list(gDatto_net_state.uci_ctx, tmp_buf, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);

			snprintf(tmp_vlan_buf, sizeof(tmp_vlan_buf), "br-ssid%d_vlan", ssid_idx_add + 1);
			ng_uci_del_list(gDatto_net_state.uci_ctx, tmp_vlan_buf, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);

			if (ssid_idx_add != ssid_idx) {
				ng_uci_add_list(gDatto_net_state.uci_ctx, tmp_buf, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
				ng_uci_add_list(gDatto_net_state.uci_ctx, tmp_vlan_buf, uci_addr_dhcp_ssid_dns_notinterface, ssid_idx + 1);
			}
		}
	}
}

// TODO: remove ap_mgr section after switch to usteerd.
static void wifi_write_ap_mgr_per_ssid_config(struct wifi_settings *parsed_settings, int ssid_idx)
{
	NULL_ASSERT(VOID_RETURN_VALUE, parsed_settings);

	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX)) {
		debug_msg_err("Passed SSID index is out of range, passed %d vs max %d", ssid_idx, SSID_MAX);
		return;
	}

	/* If the ap_mgr.ssidX=ap_mgr section doesn't exist, create it */
	if ((ng_uci_sec_exists(AP_MGR_UCI_SSID, ssid_idx + 1) != 1) && (ng_uci_tmp_named_sec(AP_MGR_UCI_SSID "=ap_mgr", ssid_idx + 1) != 1)) {
		debug_msg_err("Unable to create ssid%d UCI section for ap_mgr", ssid_idx + 1);
		return;
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].band_steering, uci_addr_ap_mgr_band_steering_enabled, ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].roaming_80211v, uci_addr_ap_mgr_roaming_enabled, ssid_idx + 1);
}

static void write_config_acl_update(struct vlist_tree OM_UNUSED(*tree), struct vlist_node *running_acl_node, struct vlist_node *parsed_acl_node)
{
	/*
	 * This implementation of vlist is "backwards" from the normal usage due to the need
	 * to only do UCI updates in this "write_config" process, and not during the "parse_config"
	 * process.  Please do not use this as a reference implementation for vlists in
	 * general.
	 */
	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	/* Do list updates first */
	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx) {
		if (parsed_acl_node && !running_acl_node) {
			struct acl_list_entry *parsed_acl_entry = container_of(parsed_acl_node, struct acl_list_entry, vlist_node);

			ng_uci_del_list(gDatto_net_state.uci_ctx, parsed_acl_entry->mac, uci_addr_ap_maclist, radio_idx, parsed_acl_entry->ssid_idx + 1);
			ng_uci_add_list(gDatto_net_state.uci_ctx, parsed_acl_entry->mac, uci_addr_ap_maclist, radio_idx, parsed_acl_entry->ssid_idx + 1);
		} else if (running_acl_node && !parsed_acl_node) {
			struct acl_list_entry *running_acl_entry = container_of(running_acl_node, struct acl_list_entry, vlist_node);

			ng_uci_del_list(gDatto_net_state.uci_ctx, running_acl_entry->mac, uci_addr_ap_maclist, radio_idx, running_acl_entry->ssid_idx + 1);
		}
	}

	/* Do cleanup of nodes unlinked from the vlist */
	if (parsed_acl_node) {
		struct acl_list_entry *parsed_acl_entry = container_of(parsed_acl_node, struct acl_list_entry, vlist_node);

		free(parsed_acl_entry); /* NOT explicitly set to NULL, immediate return */
		return;
	}
}

static void wifi_write_acl_list_config(struct wifi_settings *parsed_settings, int ssid_idx)
{
	NULL_ASSERT(VOID_RETURN_VALUE, parsed_settings);

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx)
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_ap_macfilter, radio_idx, ssid_idx + 1);

	if (!parsed_settings->ssid[ssid_idx].acl_vlist) {
		debug_msg_notice("No valid ACL for ssid %d", ssid_idx);
		return;
	}

	parsed_settings->ssid[ssid_idx].acl_vlist->update = write_config_acl_update;

	struct acl_list_entry *parsed_acl_entry = NULL;

	/*
	 * There isn't a good "is vlist empty" check, so we'll just loop over vlist entries,
	 * and break after the first iteration
	 */
	vlist_for_each_element(parsed_settings->ssid[ssid_idx].acl_vlist, parsed_acl_entry, vlist_node) {
		for (int radio_idx = 0; radio_idx < ap_radio_max; ++radio_idx)
			ng_uci_set_string(gDatto_net_state.uci_ctx, "allow", uci_addr_ap_macfilter, radio_idx, ssid_idx + 1);

		break;
	}

	/*
	 * We've got all of our "new" entries in our parsed vlist, so now start adding all of
	 * the "current/old" entries to generate all of the UCI writes we need.
	 *
	 * This is backwards from normal vlist operation, and shouldn't be used as a
	 * reference implementation.
	 */

	vlist_update(parsed_settings->ssid[ssid_idx].acl_vlist);

	if (gWifi_settings.ssid[ssid_idx].acl_vlist) {
		struct acl_list_entry *running_acl_entry = NULL;

		vlist_for_each_element(gWifi_settings.ssid[ssid_idx].acl_vlist, running_acl_entry, vlist_node) {
			struct acl_list_entry *new_acl_entry = calloc(1, sizeof(*new_acl_entry));

			if (!new_acl_entry) {
				debug_msg_notice("Unable to allocate memory to handle updating ssid %d ACL entry '%s'", ssid_idx, running_acl_entry->mac);
				continue;
			}

			snprintf(new_acl_entry->mac, sizeof(new_acl_entry->mac), "%s", running_acl_entry->mac);
			new_acl_entry->ssid_idx = ssid_idx;
			vlist_add(parsed_settings->ssid[ssid_idx].acl_vlist, &new_acl_entry->vlist_node, new_acl_entry->mac);
		}
	}
	vlist_flush(parsed_settings->ssid[ssid_idx].acl_vlist);
}

/* Returns:
 *	-1 on failure
 *	0 on success
 */
int wifid_write_ssid_config(struct wifi_settings *parsed_settings, int ssid_idx)
{
	NULL_ASSERT(-1, parsed_settings);

	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX))
		return -1;

	char ssid_str[32] = {0};

	snprintf(ssid_str, sizeof(ssid_str), "ssid%d", ssid_idx + 1);

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].enable, uci_addr_ssid_enable, ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].wifi_scheduling, uci_addr_ssid_wifi_scheduling, ssid_idx + 1);

	if (!parsed_settings->ssid[ssid_idx].dhcp.relay[0]) {
		/* set up the default dhcp.ssidX section in case we're coming from a previously relayed
		 * ssid without one
		 */
		if (ng_uci_sec_exists(DATTO_NET_UCI_DHCP_SSID, ssid_idx + 1) != 1) {
			ng_uci_set_string(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP, DATTO_NET_UCI_DHCP_SSID, ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_str, DATTO_NET_UCI_DHCP_SSID ".interface", ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, "server", DATTO_NET_UCI_DHCP_SSID ".dhcpv6", ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, "server", DATTO_NET_UCI_DHCP_SSID ".ra", ssid_idx + 1);
		}

		/* make sure any previous relays are cleaned up */
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_RELAY_FMT, ssid_idx + 1);
	}

	/* LAN stuff */
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].bridge_to_lan, uci_addr_ssid_bridge_to_lan, ssid_idx + 1);

	if (gDatto_net_state.inet_test.upstream_state == DATTO_NET_UPSTREAM_WAN_STATE) {
		/* If the SSID is disabled _don't_ touch the lan_dns dnsmasq instance ignore setting.
		 * Changing it results in the lan_dns dnsmasq instance restarting.
		 */
		if (parsed_settings->ssid[ssid_idx].enable)
			ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].bridge_to_lan, uci_addr_dhcp_ssid_ignore, ssid_idx + 1);
	} else {
		ng_uci_set_int(gDatto_net_state.uci_ctx, 1, uci_addr_dhcp_ssid_ignore, ssid_idx + 1);
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].lan_block, uci_addr_firewall_datto_lan_block, ssid_idx + 1);

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].vlan_tag, uci_addr_ssid_vid, ssid_idx + 1);

	/* If we have a valid vlan tag set up dhcp as a relay */
	if (VALID_VLAN_TAG(parsed_settings->ssid[ssid_idx].vlan_tag)) {
		ng_uci_set_string(gDatto_net_state.uci_ctx, "relay", DATTO_NET_UCI_DHCP_SSID ".dhcpv6", ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, "relay", DATTO_NET_UCI_DHCP_SSID ".ra", ssid_idx + 1);
	} else {
		ng_uci_set_string(gDatto_net_state.uci_ctx, "server", DATTO_NET_UCI_DHCP_SSID ".dhcpv6", ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, "server", DATTO_NET_UCI_DHCP_SSID ".ra", ssid_idx + 1);
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dns_intercept, uci_addr_ssid_dns_intercept, ssid_idx + 1);

	/* DHCP and static IP stuff */
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.enable, uci_addr_ssid_custom_dhcp, ssid_idx + 1);

	char ssid_ip_str[32] = {0};

	if (parsed_settings->ssid[ssid_idx].dhcp.enable) {
		ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.gateway, uci_addr_ssid_ipaddr, ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.netmask, uci_addr_ssid_netmask, ssid_idx + 1);
		ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.start, uci_addr_dhcp_ssid_start, ssid_idx + 1);
		ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.num_leases, uci_addr_dhcp_ssid_limit, ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.lease_len, uci_addr_dhcp_ssid_leasetime, ssid_idx + 1);
		if (parsed_settings->ssid[ssid_idx].dhcp.relay[0]) {
			ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_RELAY_FMT, ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, "relay", DATTO_NET_UCI_DHCP_RELAY_FMT, ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.gateway, uci_addr_dhcp_relay_local_addr, ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dhcp.relay, uci_addr_dhcp_relay_server_addr, ssid_idx + 1);
			ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_str, uci_addr_dhcp_relay_interface, ssid_idx + 1);
			ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_SSID, ssid_idx + 1);
		}

		/* Set up masquerading */
		char masq_addr[32] = {0};
		int netmask = 0;
		int net_prefix = 0;

		inet_pton(AF_INET, parsed_settings->ssid[ssid_idx].dhcp.netmask, &netmask);
		net_prefix = __builtin_popcount(netmask);

		snprintf(masq_addr, sizeof(masq_addr), "%s/%d", parsed_settings->ssid[ssid_idx].dhcp.gateway, net_prefix);
		for (int wired_bridge = 0; wired_bridge < WIRED_MAX; ++wired_bridge)
			ng_uci_add_list(gDatto_net_state.uci_ctx, masq_addr, uci_addr_firewall_wired_masq_src, wired_bridge);
	} else {
		uint16_t ip_id = get_ip_id(parsed_settings->node_id);

		/* FORM: ssid_ip = ip_id - (ssid + 1) * 4, where normal SSIDs are 1-based and mesh is 0 */
		int ssid_ip = ip_id - (ssid_idx + 1 + 1) * 4;

		snprintf(ssid_ip_str, sizeof(ssid_ip_str), "10.%d.%d.1", (uint8_t) (ssid_ip >> 8), (uint8_t) ssid_ip);

		ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_ip_str, uci_addr_ssid_ipaddr, ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, "255.255.252.0", uci_addr_ssid_netmask, ssid_idx + 1);
		ng_uci_set_int(gDatto_net_state.uci_ctx, 20, uci_addr_dhcp_ssid_start, ssid_idx + 1);
		ng_uci_set_int(gDatto_net_state.uci_ctx, 1000, uci_addr_dhcp_ssid_limit, ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, "5m", uci_addr_dhcp_ssid_leasetime, ssid_idx + 1);

		snprintf(ssid_ip_str, sizeof(ssid_ip_str), "10.%d.%d.1/22", (uint8_t) (ssid_ip >> 8), (uint8_t) ssid_ip);
		for (int wired_bridge = 0; wired_bridge < WIRED_MAX; ++wired_bridge)
			ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_ip_str, uci_addr_firewall_wired_masq_src, wired_bridge);

		if (ssid_idx == 0) {
			/* Clear the altnet from both all wired bridges */
			ng_uci_delete(gDatto_net_state.uci_ctx, "igmpproxy.wired0.altnet");
			ng_uci_delete(gDatto_net_state.uci_ctx, "igmpproxy.wired1.altnet");
		}
	}

	/* Captive portal firewall rules */

	/* Use whichever IP got set above */
	ng_uci_data_get_val(ssid_ip_str, sizeof(ssid_ip_str), uci_addr_ssid_ipaddr, ssid_idx + 1);

	/* This rule is enabled and disabled by traffic_cop but requires datto_net to setup the IP */
	ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_ip_str, uci_addr_firewall_ssid_cp_src_dip, ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_ip_str, uci_addr_firewall_ssid_lan_cp_src_dip, ssid_idx + 1);

	/* Only update the lan_dns DNS settings for SSIDs that are enabled. If the SSID is not enabled
	 * don't update the lan_dns DNS settings related to it. Doing so could cause dnsmasq instances
	 * to restart when they don't need to.
	 */
	if (!parsed_settings->ssid[ssid_idx].enable) {
		/* This SSID is disabled, delete any per-ssid dnsmasq UCI settings */
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_SSID_DNS, ssid_idx + 1);
	} else if (parsed_settings->ssid[ssid_idx].dns_intercept) {
		wifid_write_ssid_dns_intercept_config(parsed_settings, ssid_idx);
	} else {
		char ssid_br_str[32] = {0};
		char ssid_vlan_str[32] = {0};

		snprintf(ssid_br_str, sizeof(ssid_br_str), "br-ssid%d", ssid_idx + 1);
		snprintf(ssid_vlan_str, sizeof(ssid_vlan_str), "br-ssid%d_vlan", ssid_idx + 1);

		/* We don't have per-ssid settings, delete any per-ssid dnsmasq instance */
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_DHCP_SSID_DNS, ssid_idx + 1);

		// Clean any ssid references from the "main" DNS instance interface, then re-add as needed
		ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_br_str, DATTO_NET_UCI_DHCP ".lan_dns.interface");
		ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_br_str, DATTO_NET_UCI_DHCP ".lan_dns.notinterface");

		ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_vlan_str, DATTO_NET_UCI_DHCP ".lan_dns.interface");
		ng_uci_del_list(gDatto_net_state.uci_ctx, ssid_vlan_str, DATTO_NET_UCI_DHCP ".lan_dns.notinterface");

		/* Primary path (not relayed) */
		if (!parsed_settings->ssid[ssid_idx].dhcp.relay[0]) {
			/* Add the ssid into the "main" DNS instance */
			ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_br_str, DATTO_NET_UCI_DHCP ".lan_dns.interface");
			ng_uci_add_list(gDatto_net_state.uci_ctx, ssid_vlan_str, DATTO_NET_UCI_DHCP ".lan_dns.interface");

			/* Add the DHCP pool to the "main" DNS instance */
			ng_uci_set_string(gDatto_net_state.uci_ctx, "lan_dns", DATTO_NET_UCI_DHCP_SSID ".instance", ssid_idx + 1);
		}
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].rebind_protection, DATTO_NET_UCI_DHCP_SSID_DNS ".rebind_protection", ssid_idx + 1);

	if (parsed_settings->ssid[ssid_idx].smtp_redir[0]) {
		ng_uci_tmp_sec("redirect", DATTO_NET_UCI_FIREWALL_SMTP, ssid_idx + 1);

		ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_str, DATTO_NET_UCI_FIREWALL_SMTP ".src", ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].smtp_redir, uci_addr_firewall_smtp_redirect, ssid_idx + 1);
		ng_uci_set_int(gDatto_net_state.uci_ctx, 25, DATTO_NET_UCI_FIREWALL_SMTP ".dest_port", ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, "tcp", DATTO_NET_UCI_FIREWALL_SMTP ".proto", ssid_idx + 1);
		ng_uci_set_string(gDatto_net_state.uci_ctx, "DNAT", DATTO_NET_UCI_FIREWALL_SMTP ".target", ssid_idx + 1);
	} else {
		ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_FIREWALL_SMTP, ssid_idx + 1);
	}

	for (int j = 0; j < WIRED_MAX; ++j) {
		if (parsed_settings->ssid[ssid_idx].lan_block) {
			ng_uci_tmp_sec("forwarding", DATTO_NET_UCI_FIREWALL_WIRED, ssid_idx + 1, j);
			ng_uci_set_string(gDatto_net_state.uci_ctx, ssid_str, DATTO_NET_UCI_FIREWALL_WIRED ".src", ssid_idx + 1, j);

			char wired_str[IFNAMSIZ] = {0};

			snprintf(wired_str, sizeof(wired_str), "wired%d", j);

			ng_uci_set_string(gDatto_net_state.uci_ctx, wired_str, DATTO_NET_UCI_FIREWALL_WIRED ".src", ssid_idx + 1, j);
		} else {
			ng_uci_delete(gDatto_net_state.uci_ctx, DATTO_NET_UCI_FIREWALL_WIRED, ssid_idx + 1, j);
		}
	}

	/* Write out per-ssid settings to ap_mgr's config */
	wifi_write_ap_mgr_per_ssid_config(parsed_settings, ssid_idx);

	wifi_write_acl_list_config(parsed_settings, ssid_idx);

	return 0;
}

/* Returns:
 *	-1 on failure
 *	0 if the ap iface is disabled (or scanning)
 *	1 if the ap iface is enabled
 */
int wifid_write_ap_iface_config(struct wifi_settings *parsed_settings, int ssid_idx, int radio_idx)
{
	NULL_ASSERT(-1, parsed_settings);

	int ap_radio_max = (platform_wireless_get_num_radios() < RADIO_MAX) ? platform_wireless_get_num_radios() : RADIO_MAX;

	if (OUT_OF_RANGE(radio_idx, 0, ap_radio_max - 1))
		return -1;

	if (!IS_VALID_ARRAY_INDEX(ssid_idx, SSID_MAX))
		return -1;

	if (!parsed_settings->ssid[ssid_idx].parsed) {
		debug_msg_info("ssid %d wasn't parsed, not writing config for ap%d_%d", ssid_idx + 1, radio_idx, ssid_idx + 1);
		return -1;
	}

	int enable = wifid_is_ssid_band_enabled(parsed_settings, ssid_idx, radio_idx);

	if (!enable)
		return 0;

	char *name = parsed_settings->ssid[ssid_idx].ssid;
	int band = wifid_find_band(radio_idx);

	if (!IS_VALID_ARRAY_INDEX(band, BAND_MAX)) {
		debug_msg_err("Failed to find band for radio_idx: %d", radio_idx);
		return -1;
	}

	if (parsed_settings->ssid[ssid_idx].band[band].ssid[0])
		name = parsed_settings->ssid[ssid_idx].band[band].ssid;

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].band[band].start_disabled, uci_addr_ap_start_disabled, radio_idx, ssid_idx + 1);

	ng_uci_set_string(gDatto_net_state.uci_ctx, name, uci_addr_ap_ssid, radio_idx, ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].key, uci_addr_ap_key, radio_idx, ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].enc, uci_addr_ap_encryption, radio_idx, ssid_idx + 1);

	/* Test for WPA3 and set management ciphers accordingly. WPA3-mixed mode cannot enforce this as
	 * it will break backward compatibility.
	 */
	if (!strncmp(parsed_settings->ssid[ssid_idx].enc, "wpa3", sizeof(parsed_settings->ssid[ssid_idx].enc)))
		ng_uci_set_string(gDatto_net_state.uci_ctx, "BIP-GMAC-256", uci_addr_ap_ieee80211w_mgmt_cipher, radio_idx, ssid_idx + 1);
	else
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_ap_ieee80211w_mgmt_cipher, radio_idx, ssid_idx + 1);

	/* With WPA2/WPA PSK encryption the 802.11r FT PSK can be generated locally, so enable
	 * ft_psk_generate_local. This cannot be done with other encryption methods as the keys between
	 * each AP and the station are unique and connect be generated locally.
	 */
	bool enable_ft_psk_generate_local =
		!strncmp(parsed_settings->ssid[ssid_idx].enc, "psk-mixed", sizeof(parsed_settings->ssid[ssid_idx].enc)) ||
		!strncmp(parsed_settings->ssid[ssid_idx].enc, "psk2", sizeof(parsed_settings->ssid[ssid_idx].enc));

	ng_uci_set_int(gDatto_net_state.uci_ctx, enable_ft_psk_generate_local, uci_addr_ap_ft_psk_generate_local, radio_idx, ssid_idx + 1);

	/* Enable ft_over_ds by default */
	bool enable_ft_over_ds = true;

	/* FT-over-DS roaming on WPA3 Enterprise is currently broken. If this SSID is using this
	 * encryption type, disable ft_over_ds so clients will not attempt this roaming type.
	 * Otherwise enable FT-over-DS roaming for all other encryption types
	 */
	if (!strncmp(parsed_settings->ssid[ssid_idx].enc, "wpa3", sizeof(parsed_settings->ssid[ssid_idx].enc)))
		enable_ft_over_ds = false;

	ng_uci_set_int(gDatto_net_state.uci_ctx, enable_ft_over_ds, uci_addr_ap_ft_over_ds, radio_idx, ssid_idx + 1);

	/* set isolate for batman and uds */
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].client_isolate, uci_addr_ap_isolate, radio_idx, ssid_idx + 1);

	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].radius_server, uci_addr_ap_auth_server, radio_idx, ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].radius_key, uci_addr_ap_auth_secret, radio_idx, ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].radius_port, uci_addr_ap_auth_port, radio_idx, ssid_idx + 1);

	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].radius_acct_server, uci_addr_ap_acct_server, radio_idx, ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].radius_acct_key, uci_addr_ap_acct_secret, radio_idx, ssid_idx + 1);
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].radius_acct_port, uci_addr_ap_acct_port, radio_idx, ssid_idx + 1);

	ng_uci_set_int(gDatto_net_state.uci_ctx, !!parsed_settings->ssid[ssid_idx].roaming_domain[0], uci_addr_ap_ieee80211r, radio_idx, ssid_idx + 1);
	ng_uci_set_string(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].roaming_domain, uci_addr_ap_mobility_domain, radio_idx, ssid_idx + 1);

	/* Set which bridge hostapd should use for FT auth requests for this AP interface */
	if (parsed_settings->ssid[ssid_idx].roaming_domain[0]) {
		char dest_bridge[IFNAMSIZ] = {0};

		determine_dest_ssid_bridge(parsed_settings, dest_bridge, sizeof(dest_bridge), ssid_idx);
		ng_uci_set_string(gDatto_net_state.uci_ctx, dest_bridge, uci_addr_ap_ft_auth_bridge, radio_idx, ssid_idx + 1);
	}

	if (parsed_settings->ssid[ssid_idx].roaming_key[0]) {
		// Needs to be 64 (roaming key) + 18 (MAC addr) + 18 (MAX addr) and delimiters for r1kh
		char roaming_key[128] = {0};

		/* r0kh wildcard is 'ff:ff:ff:ff:ff:ff,*,<key>' */
		snprintf(roaming_key, sizeof(roaming_key), "ff:ff:ff:ff:ff:ff,*,%s", parsed_settings->ssid[ssid_idx].roaming_key);
		ng_uci_set_string(gDatto_net_state.uci_ctx, roaming_key, uci_addr_ap_r0kh, radio_idx, ssid_idx + 1);

		/* r1kh wildcard is '00:00:00:00:00:00,00:00:00:00:00:00,<key>' */
		snprintf(roaming_key, sizeof(roaming_key), "00:00:00:00:00:00,00:00:00:00:00:00,%s", parsed_settings->ssid[ssid_idx].roaming_key);
		ng_uci_set_string(gDatto_net_state.uci_ctx, roaming_key, uci_addr_ap_r1kh, radio_idx, ssid_idx + 1);
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].hidden, uci_addr_ap_hidden, radio_idx, ssid_idx + 1);

	/* Set mcast rates when lower rates are disabled */
	switch (parsed_settings->radio[radio_idx].disable_lower_rates) {
	case PHY_RATE_DISABLE_ALL_LOWER_RATES:
		ng_uci_set_int(gDatto_net_state.uci_ctx, 24000, uci_addr_ap_mcast_rate, radio_idx, ssid_idx + 1);
		break;

	case PHY_RATE_DISABLE_11B_RATES:
		ng_uci_set_int(gDatto_net_state.uci_ctx, 6000, uci_addr_ap_mcast_rate, radio_idx, ssid_idx + 1);
		break;

	case PHY_RATE_DISABLE_CUSTOM_RATES:
		/* Though the mcast_rate is set in wifid_write_radio_config(), it is possible for that
		 * function to exit before this setting is checked and set.
		 */
		if (wifid_minimum_data_rate_is_valid(parsed_settings->radio[radio_idx].mcast_rate))
			ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->radio[radio_idx].mcast_rate, uci_addr_ap_mcast_rate, radio_idx, ssid_idx + 1);
		else
			ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_ap_mcast_rate, radio_idx, ssid_idx + 1);

		break;

	default:
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_ap_mcast_rate, radio_idx, ssid_idx + 1);
	}

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].neigh_report, uci_addr_ap_neighbor_reports, radio_idx, ssid_idx + 1);

	/* A value of 2 in the UCI setting requires VLAN info in the RADIUS response or the client will
	 * be deauthed
	 */
	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dynamic_vlan ? 2 : 0, uci_addr_ap_dynamic_vlan, radio_idx, ssid_idx + 1);

	ng_uci_set_int(gDatto_net_state.uci_ctx, parsed_settings->ssid[ssid_idx].dtim_interval, uci_addr_ap_dtim_interval, radio_idx, ssid_idx + 1);

	if (parsed_settings->ssid[ssid_idx].dynamic_vlan) {
		ng_uci_set_string(gDatto_net_state.uci_ctx, "br-vlan", uci_addr_ap_vlan_bridge, radio_idx, ssid_idx + 1);
		if (gDatto_net_state.current_wired_uplink[0]) {
			int iface_num = -1;

			if (sscanf(gDatto_net_state.current_wired_uplink, "br-wired%i", &iface_num) == EOF) {
				debug_msg_err("Failed to find which ethernet interface to use for dynamic vlan tagging");
			} else {
				char eth_id[IFNAMSIZ] = {0};

				snprintf(eth_id, sizeof(eth_id), "eth%d", iface_num);
				ng_uci_set_string(gDatto_net_state.uci_ctx, eth_id, uci_addr_ap_vlan_tagged_interface, radio_idx, ssid_idx + 1);
			}
		}
	} else {
		ng_uci_delete(gDatto_net_state.uci_ctx, uci_addr_ap_vlan_bridge, radio_idx, ssid_idx + 1);
	}

	return 1;
}

enum {
	BANDS_BAND,
	BANDS_ENABLE,
	BANDS_SSID,
	__BANDS_MAX
};

static const struct blobmsg_policy band_policy[] = {
	[BANDS_BAND] = { "band", BLOBMSG_TYPE_STRING },
	[BANDS_ENABLE] = { "enable", BLOBMSG_TYPE_BOOL },
	[BANDS_SSID] = { "ssid", BLOBMSG_TYPE_STRING },
};

// All params must be verified by calling function
static int wifid_parse_band_data(struct wifi_settings *parsed_settings, int _ssid, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__BANDS_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(band_policy, __BANDS_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!parsed_data[BANDS_BAND]) {
		debug_msg_err("bands array object doesn't contain a 'band' member");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	int band_idx = wifid_find_band_by_type(blobmsg_get_string(parsed_data[BANDS_BAND]));

	if (wifid_find_radio(band_idx) < 0) {
		debug_msg_err("Invalid band: %d:%s", band_idx, blobmsg_get_string(parsed_data[BANDS_BAND]));
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	TB_BOOL(BANDS_ENABLE, parsed_settings->ssid[_ssid].band[band_idx].enable);
	TB_STRING(BANDS_SSID, parsed_settings->ssid[_ssid].band[band_idx].ssid);

	/* If there's a per-band setting, use that. If not, use the global SSID setting */
	parsed_settings->ssid[_ssid].band[band_idx].start_disabled = (parsed_settings->ssid[_ssid].band[band_idx].ssid[0]) ? !parsed_settings->ssid[_ssid].band[band_idx].enable : !parsed_settings->ssid[_ssid].enable;

	return UBUS_STATUS_OK;
}

// All params must be verified by calling function
static int wifid_parse_bands(struct wifi_settings *parsed_settings, int _ssid, struct blob_attr *msg)
{
	struct blob_attr *pos = NULL;
	int rem = 0;

	debug_blobmsg_dump(msg);

	blobmsg_for_each_attr(pos, msg, rem) {
		int ret = wifid_parse_band_data(parsed_settings, _ssid, pos);

		if (ret != UBUS_STATUS_OK)
			return ret;
	}

	return UBUS_STATUS_OK;
}

// All params must be verified by calling function
static int wifid_parse_acl(struct wifi_settings *parsed_settings, int _ssid, struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;

	if (!parsed_settings->ssid[_ssid].acl_vlist) {
		debug_msg_err("No ACL list exists, previous memory error?");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	/* We got a new ACL, clear out the old one */
	vlist_flush_all(parsed_settings->ssid[_ssid].acl_vlist);
	parsed_settings->ssid[_ssid].acl_vlist->version = 1;

	blobmsg_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		char *acl = blobmsg_get_string(cur);

		if (!str_is_mac_addr(acl)) {
			debug_msg_notice("Got incorrect format for acl '%s'", acl);
			continue;
		}

		struct acl_list_entry *new_acl_entry = calloc(1, sizeof(*new_acl_entry));

		if (!new_acl_entry) {
			debug_msg_notice("Unable to allocate memory to add acl entry to ssid %d for '%s'", _ssid, acl);
			continue;
		}

		snprintf(new_acl_entry->mac, sizeof(new_acl_entry->mac), "%s", acl);
		new_acl_entry->ssid_idx = _ssid;
		vlist_add(parsed_settings->ssid[_ssid].acl_vlist, &new_acl_entry->vlist_node, new_acl_entry->mac);
	}

	return UBUS_STATUS_OK;
}

// All params must be verified by calling function
static int wifid_parse_dns(struct wifi_settings *parsed_settings, int _ssid, struct blob_attr *msg)
{
	struct blob_attr *cur;
	int rem;
	int cnt = 0;

	/* We got a new DNS server list, clear out the old one */
	memset(parsed_settings->ssid[_ssid].dns_server, 0, sizeof(parsed_settings->ssid[_ssid].dns_server));

	blobmsg_for_each_attr(cur, msg, rem) {
		if (blobmsg_type(cur) != BLOBMSG_TYPE_STRING)
			continue;

		char *dns = blobmsg_get_string(cur);

		snprintf(parsed_settings->ssid[_ssid].dns_server[cnt], sizeof(parsed_settings->ssid[_ssid].dns_server[0]), "%s", dns);

		if (++cnt >= DNS_MAX)
			break;
	}

	return UBUS_STATUS_OK;
}

enum {
	DHCP_ENABLE,
	DHCP_GATEWAY,
	DHCP_NETMASK,
	DHCP_RELAY,
	DHCP_START,
	DHCP_NUM_LEASES,
	DHCP_LEASE_LEN,
	__DHCP_MAX
};

static const struct blobmsg_policy dhcp_policy[] = {
	[DHCP_ENABLE] = { "enable", BLOBMSG_TYPE_BOOL },
	[DHCP_GATEWAY] = { "gateway_ip", BLOBMSG_TYPE_STRING },
	[DHCP_NETMASK] = { "netmask", BLOBMSG_TYPE_STRING },
	[DHCP_RELAY] = { "relay", BLOBMSG_TYPE_STRING },
	[DHCP_START] = { "start", BLOBMSG_TYPE_INT32 },
	[DHCP_NUM_LEASES] = { "num_leases", BLOBMSG_TYPE_INT32 },
	[DHCP_LEASE_LEN] = { "lease_length", BLOBMSG_TYPE_STRING },
};

// All params must be verified by calling function
static int wifid_parse_dhcp(struct wifi_settings *parsed_settings, int _ssid, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__DHCP_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(dhcp_policy, __DHCP_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!parsed_data[DHCP_ENABLE]) {
		debug_msg_err("Unable to get DHCP enable");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	parsed_settings->ssid[_ssid].dhcp.enable = blobmsg_get_bool(parsed_data[DHCP_ENABLE]);

	if (!parsed_settings->ssid[_ssid].dhcp.enable) {
		/* Ensure relay is emptied out, because we check against it elsewhere */
		parsed_settings->ssid[_ssid].dhcp.relay[0] = '\0';
		return UBUS_STATUS_OK;
	}

	TB_STRING(DHCP_GATEWAY, parsed_settings->ssid[_ssid].dhcp.gateway);
	TB_STRING(DHCP_NETMASK, parsed_settings->ssid[_ssid].dhcp.netmask);
	TB_STRING(DHCP_RELAY, parsed_settings->ssid[_ssid].dhcp.relay);
	TB_INT(DHCP_START, parsed_settings->ssid[_ssid].dhcp.start);
	TB_INT(DHCP_NUM_LEASES, parsed_settings->ssid[_ssid].dhcp.num_leases);
	TB_STRING(DHCP_LEASE_LEN, parsed_settings->ssid[_ssid].dhcp.lease_len);

	return UBUS_STATUS_OK;
}

enum {
	SSID_INDEX,
	SSID_ENABLE,
	SSID_SSID,
	SSID_KEY,
	SSID_ENC,
	SSID_RADIUS_SERVER,
	SSID_RADIUS_PORT,
	SSID_RADIUS_KEY,
	SSID_VLAN_TAG,
	SSID_BRIDGE_TO_LAN,
	SSID_REBIND_PROTECTION,
	SSID_ROAMING_DOMAIN,
	SSID_ROAMING_KEY,
	SSID_RADIUS_ACCT_SERVER,
	SSID_RADIUS_ACCT_KEY,
	SSID_RADIUS_ACCT_PORT,
	SSID_NEIGH_REPORT,
	SSID_ANYIP,
	SSID_LAN_BLOCK,
	SSID_CLIENT_ISOLATE,
	SSID_SMTP_REDIR,
	SSID_DNS_SERVER,
	SSID_BAND,
	SSID_ACL,
	SSID_HIDDEN,
	SSID_DHCP,
	SSID_DNS_INTERCEPT,
	SSID_DNS_CACHE_ENABLE,
	SSID_BAND_STEERING,
	SSID_ROAMING_80211V,
	SSID_WIFI_SCHEDULING,
	SSID_DYNAMIC_VLAN,
	SSID_DTIM_INTERVAL,
	__SSID_MAX
};

static const struct blobmsg_policy ssid_policy[] = {
	[SSID_INDEX] = { "index", BLOBMSG_TYPE_INT32 },
	[SSID_ENABLE] = { "enable", BLOBMSG_TYPE_BOOL },
	[SSID_SSID] = { "ssid", BLOBMSG_TYPE_STRING },
	[SSID_KEY] = { "key", BLOBMSG_TYPE_STRING },
	[SSID_ENC] = { "enc", BLOBMSG_TYPE_STRING },
	[SSID_RADIUS_SERVER] = { "radius_server", BLOBMSG_TYPE_STRING },
	[SSID_RADIUS_PORT] = { "radius_port", BLOBMSG_TYPE_INT32 },
	[SSID_RADIUS_KEY] = { "radius_key", BLOBMSG_TYPE_STRING },
	[SSID_VLAN_TAG] = { "vlan_tag", BLOBMSG_TYPE_INT32 },
	[SSID_BRIDGE_TO_LAN] = { "bridge_to_lan", BLOBMSG_TYPE_BOOL },
	[SSID_REBIND_PROTECTION] = { "rebind_protection", BLOBMSG_TYPE_BOOL },
	[SSID_ROAMING_DOMAIN] = { "roaming_domain", BLOBMSG_TYPE_STRING },
	[SSID_ROAMING_KEY] = { "roaming_key", BLOBMSG_TYPE_STRING },
	[SSID_RADIUS_ACCT_SERVER] = { "radius_acct_server", BLOBMSG_TYPE_STRING },
	[SSID_RADIUS_ACCT_KEY] = { "radius_acct_key", BLOBMSG_TYPE_STRING },
	[SSID_RADIUS_ACCT_PORT] = { "radius_acct_port", BLOBMSG_TYPE_INT32 },
	[SSID_NEIGH_REPORT] = { "neighbor_reports", BLOBMSG_TYPE_BOOL },
	[SSID_ANYIP] = { "anyip", BLOBMSG_TYPE_BOOL },
	[SSID_LAN_BLOCK] = { "lan_block", BLOBMSG_TYPE_BOOL },
	[SSID_CLIENT_ISOLATE] = { "client_isolation", BLOBMSG_TYPE_BOOL },
	[SSID_SMTP_REDIR] = { "smtp_redirect", BLOBMSG_TYPE_STRING },
	[SSID_DNS_SERVER] = { "dns_servers", BLOBMSG_TYPE_ARRAY },
	[SSID_BAND] = { "bands", BLOBMSG_TYPE_ARRAY },
	[SSID_ACL] = { "access_control_list", BLOBMSG_TYPE_ARRAY },
	[SSID_HIDDEN] = { "hidden", BLOBMSG_TYPE_BOOL },
	[SSID_DHCP] = { "dhcp", BLOBMSG_TYPE_TABLE },
	[SSID_DNS_INTERCEPT] = {"dns_intercept", BLOBMSG_TYPE_BOOL },
	[SSID_DNS_CACHE_ENABLE] = {"dns_cache_enable", BLOBMSG_TYPE_BOOL },
	[SSID_BAND_STEERING] = { "band_steering", BLOBMSG_TYPE_BOOL },
	[SSID_ROAMING_80211V] = { "roaming_80211v", BLOBMSG_TYPE_BOOL },
	[SSID_WIFI_SCHEDULING] = { "wifi_scheduling", BLOBMSG_TYPE_BOOL },
	[SSID_DYNAMIC_VLAN] = { "dynamic_vlan", BLOBMSG_TYPE_BOOL },
	[SSID_DTIM_INTERVAL] = { "dtim_interval", BLOBMSG_TYPE_INT32 },
};

// All params must be verified by calling function
int wifid_parse_ssid(struct wifi_settings *parsed_settings, struct blob_attr *msg)
{
	struct blob_attr *parsed_data[__SSID_MAX]; /* Zeroed out by blobmsg_parse */

	if (blobmsg_parse(ssid_policy, __SSID_MAX, parsed_data, blobmsg_data(msg), blobmsg_len(msg))) {
		debug_msg_err("Unable to parse arguments");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!parsed_data[SSID_INDEX]) {
		debug_msg_err("Failed to find 'index' key in msg");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	int idx = blobmsg_get_u32(parsed_data[SSID_INDEX]) - 1;

	if (OUT_OF_RANGE(idx, 0, SSID_MAX - 1)) {
		debug_msg_err("Invalid ssid index: %d", idx);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	TB_BOOL(SSID_ENABLE, parsed_settings->ssid[idx].enable);
	TB_STRING(SSID_SSID, parsed_settings->ssid[idx].ssid);
	TB_STRING(SSID_KEY, parsed_settings->ssid[idx].key);
	TB_STRING(SSID_ENC, parsed_settings->ssid[idx].enc);
	TB_STRING(SSID_RADIUS_SERVER, parsed_settings->ssid[idx].radius_server);
	TB_STRING(SSID_RADIUS_KEY, parsed_settings->ssid[idx].radius_key);
	TB_INT(SSID_RADIUS_PORT, parsed_settings->ssid[idx].radius_port);
	TB_INT(SSID_VLAN_TAG, parsed_settings->ssid[idx].vlan_tag);
	TB_BOOL(SSID_BRIDGE_TO_LAN, parsed_settings->ssid[idx].bridge_to_lan);
	TB_BOOL(SSID_REBIND_PROTECTION, parsed_settings->ssid[idx].rebind_protection);
	TB_STRING(SSID_ROAMING_DOMAIN, parsed_settings->ssid[idx].roaming_domain);
	TB_STRING(SSID_ROAMING_KEY, parsed_settings->ssid[idx].roaming_key);
	TB_STRING(SSID_RADIUS_ACCT_SERVER, parsed_settings->ssid[idx].radius_acct_server);
	TB_STRING(SSID_RADIUS_ACCT_KEY, parsed_settings->ssid[idx].radius_acct_key);
	TB_INT(SSID_RADIUS_ACCT_PORT, parsed_settings->ssid[idx].radius_acct_port);
	TB_BOOL(SSID_NEIGH_REPORT, parsed_settings->ssid[idx].neigh_report);
	TB_BOOL(SSID_ANYIP, parsed_settings->ssid[idx].anyip);
	TB_BOOL(SSID_LAN_BLOCK, parsed_settings->ssid[idx].lan_block);
	TB_BOOL(SSID_CLIENT_ISOLATE, parsed_settings->ssid[idx].client_isolate);
	TB_BOOL(SSID_HIDDEN, parsed_settings->ssid[idx].hidden);
	TB_STRING(SSID_SMTP_REDIR, parsed_settings->ssid[idx].smtp_redir);
	TB_BOOL(SSID_DNS_INTERCEPT, parsed_settings->ssid[idx].dns_intercept);
	TB_BOOL(SSID_DNS_CACHE_ENABLE, parsed_settings->ssid[idx].dns_cache_enable);

	/* parse out ap_mgr(usteer) per-ssid settings */
	TB_BOOL(SSID_BAND_STEERING, parsed_settings->ssid[idx].band_steering);
	TB_BOOL(SSID_ROAMING_80211V, parsed_settings->ssid[idx].roaming_80211v);

	TB_BOOL(SSID_WIFI_SCHEDULING, parsed_settings->ssid[idx].wifi_scheduling);
	TB_BOOL(SSID_DYNAMIC_VLAN, parsed_settings->ssid[idx].dynamic_vlan);

	TB_INT(SSID_DTIM_INTERVAL, parsed_settings->ssid[idx].dtim_interval);

	/* Default DTIM interval to be 2 beacon intervals */
	if (!parsed_settings->ssid[idx].dtim_interval)
		parsed_settings->ssid[idx].dtim_interval = 2;

	if (parsed_data[SSID_BAND] && wifid_parse_bands(parsed_settings, idx, parsed_data[SSID_BAND])) {
		debug_msg_err("Failed to parse band, ssid_idx = %d", idx);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (parsed_data[SSID_ACL] && wifid_parse_acl(parsed_settings, idx, parsed_data[SSID_ACL])) {
		debug_msg_err("Failed to parse acl list, ssid_idx = %d", idx);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (parsed_data[SSID_DNS_SERVER] && wifid_parse_dns(parsed_settings, idx, parsed_data[SSID_DNS_SERVER])) {
		debug_msg_err("Failed to parse DNS servers, ssid_idx = %d", idx);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (parsed_data[SSID_DHCP] && wifid_parse_dhcp(parsed_settings, idx, parsed_data[SSID_DHCP])) {
		debug_msg_err("Failed to parse DHCP settings, ssid_idx = %d", idx);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	parsed_settings->ssid[idx].parsed = true;

	return UBUS_STATUS_OK;
}
