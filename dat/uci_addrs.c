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
#include "wifi/settings/uci_addrs.h"

const char uci_addr_antenna[] =							DATTO_NET_UCI_FILE ".local.antenna";
const char uci_addr_datto_net_debug_level[] =			DATTO_NET_UCI_FILE ".debug.debug_level";
const char uci_addr_delayed_wifi[] =					DATTO_NET_UCI_FILE ".local.delayed_wifi";
const char uci_addr_outdoor[] =							DATTO_NET_UCI_FILE ".local.outdoor";
const char uci_addr_override_reason[] =					DATTO_NET_UCI_FILE ".local.override_reason";
const char uci_addr_radio_override[] =					DATTO_NET_UCI_FILE ".local.radio_override";
const char uci_addr_recover_config[] =					DATTO_NET_UCI_FILE ".local.recover_config_errors";

const char uci_addr_radio_basic_rate[] =				DATTO_NET_UCI_WIRELESS_RADIO ".basic_rate";
const char uci_addr_radio_chanlist[] =					DATTO_NET_UCI_WIRELESS_RADIO ".channels";
const char uci_addr_radio_chanlist_count[] =			DATTO_NET_UCI_WIRELESS_RADIO ".chanlist_count";
const char uci_addr_radio_channel[] =					DATTO_NET_UCI_WIRELESS_RADIO ".channel";
const char uci_addr_radio_country[] =					DATTO_NET_UCI_WIRELESS_RADIO ".country";
const char uci_addr_radio_dfs_enable[] =				DATTO_NET_UCI_WIRELESS_RADIO ".dfs_enable";
const char uci_addr_radio_disable_lower_rates[] =		DATTO_NET_UCI_WIRELESS_RADIO ".disable_lower_rates";
const char uci_addr_radio_minimum_data_rate[] =			DATTO_NET_UCI_WIRELESS_RADIO ".minimum_data_rate";
const char uci_addr_radio_legacy_rates[] =				DATTO_NET_UCI_WIRELESS_RADIO ".legacy_rates";
const char uci_addr_radio_enable[] =					DATTO_NET_UCI_WIRELESS_RADIO ".enable";
const char uci_addr_radio_htmode[] =					DATTO_NET_UCI_WIRELESS_RADIO ".htmode";
const char uci_addr_radio_noscan[] =					DATTO_NET_UCI_WIRELESS_RADIO ".noscan";
const char uci_addr_radio_rts[] =						DATTO_NET_UCI_WIRELESS_RADIO ".rts";
const char uci_addr_radio_supported_rates[] =			DATTO_NET_UCI_WIRELESS_RADIO ".supported_rates";
const char uci_addr_radio_txpower[] =					DATTO_NET_UCI_WIRELESS_RADIO ".txpower";

const char uci_addr_ap_acct_port[] =					DATTO_NET_UCI_WIRELESS_AP ".acct_port";
const char uci_addr_ap_acct_secret[] =					DATTO_NET_UCI_WIRELESS_AP ".acct_secret";
const char uci_addr_ap_acct_server[] =					DATTO_NET_UCI_WIRELESS_AP ".acct_server";
const char uci_addr_ap_auth_port[] =					DATTO_NET_UCI_WIRELESS_AP ".auth_port";
const char uci_addr_ap_auth_secret[] =					DATTO_NET_UCI_WIRELESS_AP ".auth_secret";
const char uci_addr_ap_auth_server[] =					DATTO_NET_UCI_WIRELESS_AP ".auth_server";
const char uci_addr_ap_config_enable[] =				DATTO_NET_UCI_WIRELESS_AP ".config_enable";
const char uci_addr_ap_dtim_interval[] =				DATTO_NET_UCI_WIRELESS_AP ".dtim_interval";
const char uci_addr_ap_dynamic_vlan[] =					DATTO_NET_UCI_WIRELESS_AP ".dynamic_vlan";
const char uci_addr_ap_enable[] =						DATTO_NET_UCI_WIRELESS_AP ".enable";
const char uci_addr_ap_encryption[] =					DATTO_NET_UCI_WIRELESS_AP ".encryption";

/* This is which iface hostapd will use to send and receive ft_over_ds auth requests used in
 * 802.11r ft roaming
 */
const char uci_addr_ap_ft_auth_bridge[] =				DATTO_NET_UCI_WIRELESS_AP ".ft_auth_bridge";

const char uci_addr_ap_ft_over_ds[] =					DATTO_NET_UCI_WIRELESS_AP ".ft_over_ds";
const char uci_addr_ap_ft_psk_generate_local[] =		DATTO_NET_UCI_WIRELESS_AP ".ft_psk_generate_local";
const char uci_addr_ap_hidden[] =						DATTO_NET_UCI_WIRELESS_AP ".hidden";
const char uci_addr_ap_ieee80211r[] =					DATTO_NET_UCI_WIRELESS_AP ".ieee80211r";
const char uci_addr_ap_ieee80211w_mgmt_cipher[] =		DATTO_NET_UCI_WIRELESS_AP ".ieee80211w_mgmt_cipher";
const char uci_addr_ap_isolate[] =						DATTO_NET_UCI_WIRELESS_AP ".isolate";
const char uci_addr_ap_key[] =							DATTO_NET_UCI_WIRELESS_AP ".key";
const char uci_addr_ap_macfilter[] =					DATTO_NET_UCI_WIRELESS_AP ".macfilter";
const char uci_addr_ap_maclist[] =						DATTO_NET_UCI_WIRELESS_AP ".maclist";
const char uci_addr_ap_mcast_rate[] =					DATTO_NET_UCI_WIRELESS_AP ".mcast_rate";
const char uci_addr_ap_mobility_domain[] =				DATTO_NET_UCI_WIRELESS_AP ".mobility_domain";
const char uci_addr_ap_neighbor_reports[] =				DATTO_NET_UCI_WIRELESS_AP ".neighbor_reports";
const char uci_addr_ap_r0kh[] =							DATTO_NET_UCI_WIRELESS_AP ".r0kh";
const char uci_addr_ap_r1kh[] =							DATTO_NET_UCI_WIRELESS_AP ".r1kh";
const char uci_addr_ap_ssid[] =							DATTO_NET_UCI_WIRELESS_AP ".ssid";
const char uci_addr_ap_ssidno[] =						DATTO_NET_UCI_WIRELESS_AP ".ssidno";
const char uci_addr_ap_start_disabled[] =				DATTO_NET_UCI_WIRELESS_AP ".start_disabled";
const char uci_addr_ap_vlan_bridge[] =					DATTO_NET_UCI_WIRELESS_AP ".vlan_bridge";
const char uci_addr_ap_vlan_tagged_interface[] =		DATTO_NET_UCI_WIRELESS_AP ".vlan_tagged_interface";

const char uci_addr_mesh_basic_rates[] =				DATTO_NET_UCI_WIRELESS_MESH ".mesh_basic_rates";
const char uci_addr_mesh_config_enable[] =				DATTO_NET_UCI_WIRELESS_MESH ".config_enable";
const char uci_addr_mesh_enable[] =						DATTO_NET_UCI_WIRELESS_MESH ".enable";
const char uci_addr_mesh_key[] =						DATTO_NET_UCI_WIRELESS_MESH ".key";

const char uci_addr_network_mesh_master[] =				DATTO_NET_UCI_NETWORK_MESH ".master";
const char uci_addr_network_mesh_mtu[] =				DATTO_NET_UCI_NETWORK_MESH ".mtu";
const char uci_addr_network_mesh_proto[] =				DATTO_NET_UCI_NETWORK_MESH ".proto";

const char uci_addr_orphan_enable[] =					DATTO_NET_UCI_WIRELESS_ORPHAN ".enable";
const char uci_addr_orphan_key[] =						DATTO_NET_UCI_WIRELESS_ORPHAN ".key";
const char uci_addr_orphan_macaddr[] =					DATTO_NET_UCI_WIRELESS_ORPHAN ".macaddr";

const char uci_addr_orph_conn_bssid[] =					DATTO_NET_UCI_WIRELESS_ORPH_CONN ".bssid";
const char uci_addr_orph_conn_enable[] =				DATTO_NET_UCI_WIRELESS_ORPH_CONN ".enable";
const char uci_addr_orph_conn_key[] =					DATTO_NET_UCI_WIRELESS_ORPH_CONN ".key";

const char uci_addr_batman_bridge_loop_avoidance[] =	DATTO_NET_UCI_NETWORK_BATMAN ".bridge_loop_avoidance";
const char uci_addr_batman_gw_stickiness[] =			DATTO_NET_UCI_NETWORK_BATMAN ".gw_stickiness";
const char uci_addr_batman_hop_penalty[] =				DATTO_NET_UCI_NETWORK_BATMAN ".hop_penalty";
const char uci_addr_batman_protocol[] =					DATTO_NET_UCI_NETWORK_BATMAN ".routing_algo";

const char uci_addr_ssid_bridge_to_lan[] =				DATTO_NET_UCI_NETWORK_SSID ".bridge_to_lan";
const char uci_addr_ssid_custom_dhcp[] =				DATTO_NET_UCI_NETWORK_SSID ".custom_dhcp";
const char uci_addr_ssid_dns_intercept[] =				DATTO_NET_UCI_NETWORK_SSID ".dns_intercept";
const char uci_addr_ssid_enable[] =						DATTO_NET_UCI_NETWORK_SSID ".config_enable";
const char uci_addr_ssid_ipaddr[] =						DATTO_NET_UCI_NETWORK_SSID ".ipaddr";
const char uci_addr_ssid_netmask[] =					DATTO_NET_UCI_NETWORK_SSID ".netmask";
const char uci_addr_ssid_vid[] =						DATTO_NET_UCI_NETWORK_SSID_VLAN ".vid";
const char uci_addr_ssid_wifi_scheduling[] =			DATTO_NET_UCI_NETWORK_SSID ".wifi_scheduling";

const char uci_addr_dhcp_ssid_dns_interface[] =			DATTO_NET_UCI_DHCP_SSID_DNS ".interface";
const char uci_addr_dhcp_ssid_dns_notinterface[] =		DATTO_NET_UCI_DHCP_SSID_DNS ".notinterface";
const char uci_addr_dhcp_ssid_dns_port[] =				DATTO_NET_UCI_DHCP_SSID_DNS ".port";
const char uci_addr_dhcp_ssid_dns_server[] =			DATTO_NET_UCI_DHCP_SSID_DNS ".server";
const char uci_addr_dhcp_ssid_ignore[] =				DATTO_NET_UCI_DHCP_SSID ".ignore";
const char uci_addr_dhcp_ssid_leasetime[] =				DATTO_NET_UCI_DHCP_SSID ".leasetime";
const char uci_addr_dhcp_ssid_limit[] =					DATTO_NET_UCI_DHCP_SSID ".limit";
const char uci_addr_dhcp_ssid_rebind_protection[] =		DATTO_NET_UCI_DHCP_SSID_DNS ".rebind_protection";
const char uci_addr_dhcp_ssid_start[] =					DATTO_NET_UCI_DHCP_SSID ".start";

const char uci_addr_dhcp_relay_interface[] =			DATTO_NET_UCI_DHCP_RELAY_FMT ".interface";
const char uci_addr_dhcp_relay_local_addr[] =			DATTO_NET_UCI_DHCP_RELAY_FMT ".local_addr";
const char uci_addr_dhcp_relay_server_addr[] =			DATTO_NET_UCI_DHCP_RELAY_FMT ".server_addr";

const char uci_addr_firewall_datto_lan_block[] =		DATTO_NET_UCI_FIREWALL ".datto.lan_block%d";
const char uci_addr_firewall_smtp_redirect[] =			DATTO_NET_UCI_FIREWALL_SMTP ".dest_ip";
const char uci_addr_firewall_ssid_cp_src_dip[] =		DATTO_NET_UCI_FIREWALL ".ssid%d_cp.src_dip";
const char uci_addr_firewall_ssid_lan_cp_src_dip[] =	DATTO_NET_UCI_FIREWALL ".ssid%d_lan_cp.src_dip";
const char uci_addr_firewall_wired_masq_src[] =			DATTO_NET_UCI_FIREWALL ".wired%d.masq_src";

const char uci_addr_evlog_hostapd_events[] =			"evlog.hostapd.events";

const char uci_addr_fw_core_node_id[] =					"fw_core.local.node_id";

const char uci_addr_prequestd_enable[] =				PREQUESTD_UCI_FILE ".enable";
const char uci_addr_prequestd_interface[] =				PREQUESTD_UCI_FILE ".interface";
const char uci_addr_prequestd_interval[] =				PREQUESTD_UCI_FILE ".interval";

/* u80211d automatic AP scanning config options */
const char uci_addr_u80211d_ap_force[] =				"u80211d.global.scan_ap_force";
const char uci_addr_u80211d_country[] =					"u80211d.global.country";
const char uci_addr_u80211d_scan_period[] =				"u80211d.global.scan_period";
const char uci_addr_u80211d_scan_phy[] =				"u80211d.global.scan_phy";

/* u80211d automatic channel survey config options */
const char uci_addr_u80211d_survey_dwell_time[] =		"u80211d.global.survey_dwell_time";
const char uci_addr_u80211d_survey_period[] =			"u80211d.global.survey_period";
const char uci_addr_u80211d_survey_phy[] =				"u80211d.global.survey_phy";

const char uci_addr_ap_mgr_band_steering_enabled[] =	AP_MGR_UCI_SSID ".band_steering_enabled";
const char uci_addr_ap_mgr_roaming_enabled[] =			AP_MGR_UCI_SSID ".roaming_enabled";
