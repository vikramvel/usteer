/***
 *
 * Copyright (C) 2022 Datto, Inc.
 *
 * The reproduction and distribution of this software without the written
 * consent of Datto, Inc. is prohibited by the United States Copyright
 * Act and international treaties.
 *
 ***/

#ifndef __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_UCI_ADDRS_H_
#define __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_UCI_ADDRS_H_

#define DATTO_NET_UCI_WIRELESS				"wireless"
#define DATTO_NET_UCI_WIRELESS_RADIO		DATTO_NET_UCI_WIRELESS ".radio%d"
#define DATTO_NET_UCI_WIRELESS_AP			DATTO_NET_UCI_WIRELESS ".ap%d_%d"
#define DATTO_NET_UCI_WIRELESS_MESH			DATTO_NET_UCI_WIRELESS ".mesh%d"
#define DATTO_NET_UCI_WIRELESS_ORPHAN		DATTO_NET_UCI_WIRELESS ".orphan%d"
#define DATTO_NET_UCI_WIRELESS_ORPH_CONN	DATTO_NET_UCI_WIRELESS ".orph_conn%d"

#define DATTO_NET_UCI_FIREWALL				"firewall"
#define DATTO_NET_UCI_FIREWALL_SMTP			DATTO_NET_UCI_FIREWALL ".ssid%dsmtp"
#define DATTO_NET_UCI_FIREWALL_WIRED		DATTO_NET_UCI_FIREWALL ".ssid%dwired%d"

#define DATTO_NET_UCI_NETWORK				"network"
#define DATTO_NET_UCI_NETWORK_SSID			DATTO_NET_UCI_NETWORK ".ssid%d"
#define DATTO_NET_UCI_NETWORK_SSID_VLAN		DATTO_NET_UCI_NETWORK ".ssid%d_vlan"
#define DATTO_NET_UCI_NETWORK_BATMAN		DATTO_NET_UCI_NETWORK ".bat%d"
#define DATTO_NET_UCI_NETWORK_MESH			DATTO_NET_UCI_NETWORK ".mesh%d"

#define DATTO_NET_UCI_DHCP					"dhcp"
#define DATTO_NET_UCI_DHCP_SSID				DATTO_NET_UCI_DHCP ".ssid%d"
#define DATTO_NET_UCI_DHCP_SSID_DNS			DATTO_NET_UCI_DHCP_SSID "_dns"
#define DATTO_NET_UCI_DHCP_RELAY_FMT		DATTO_NET_UCI_DHCP ".relay_ssid%d"

#define PREQUESTD_UCI_FILE					"prequestd.prequestd"

#define FIREWALL_UCI_FILE					"firewall"

#define AP_MGR_UCI							"ap_mgr"
#define AP_MGR_UCI_SSID						AP_MGR_UCI ".ssid%d"

#define USTEER_UCI							"usteer"
#define USTEER_UCI_FIRST					USTEER_UCI ".@usteer[0]"
#define USTEER_UCI_SSID_LIST				USTEER_UCI_FIRST ".ssid_list"
#define USTEER_UCI_BAND_STEER_SSID_LIST		USTEER_UCI_FIRST ".band_steer_ssid_list"

extern const char uci_addr_antenna[];
extern const char uci_addr_datto_net_debug_level[];
extern const char uci_addr_delayed_wifi[];
extern const char uci_addr_outdoor[];
extern const char uci_addr_override_reason[];
extern const char uci_addr_radio_override[];
extern const char uci_addr_recover_config[];

extern const char uci_addr_radio_basic_rate[];
extern const char uci_addr_radio_chanlist[];
extern const char uci_addr_radio_chanlist_count[];
extern const char uci_addr_radio_channel[];
extern const char uci_addr_radio_country[];
extern const char uci_addr_radio_dfs_enable[];
extern const char uci_addr_radio_disable_lower_rates[];
extern const char uci_addr_radio_minimum_data_rate[];
extern const char uci_addr_radio_legacy_rates[];
extern const char uci_addr_radio_enable[];
extern const char uci_addr_radio_htmode[];
extern const char uci_addr_radio_noscan[];
extern const char uci_addr_radio_rts[];
extern const char uci_addr_radio_supported_rates[];
extern const char uci_addr_radio_txpower[];

extern const char uci_addr_ap_acct_port[];
extern const char uci_addr_ap_acct_secret[];
extern const char uci_addr_ap_acct_server[];
extern const char uci_addr_ap_auth_port[];
extern const char uci_addr_ap_auth_secret[];
extern const char uci_addr_ap_auth_server[];
extern const char uci_addr_ap_config_enable[];
extern const char uci_addr_ap_dtim_interval[];
extern const char uci_addr_ap_dynamic_vlan[];
extern const char uci_addr_ap_enable[];
extern const char uci_addr_ap_encryption[];
extern const char uci_addr_ap_ft_auth_bridge[];
extern const char uci_addr_ap_ft_over_ds[];
extern const char uci_addr_ap_ft_psk_generate_local[];
extern const char uci_addr_ap_hidden[];
extern const char uci_addr_ap_ieee80211r[];
extern const char uci_addr_ap_ieee80211w_mgmt_cipher[];
extern const char uci_addr_ap_isolate[];
extern const char uci_addr_ap_key[];
extern const char uci_addr_ap_macfilter[];
extern const char uci_addr_ap_maclist[];
extern const char uci_addr_ap_mcast_rate[];
extern const char uci_addr_ap_mobility_domain[];
extern const char uci_addr_ap_neighbor_reports[];
extern const char uci_addr_ap_r0kh[];
extern const char uci_addr_ap_r1kh[];
extern const char uci_addr_ap_ssid[];
extern const char uci_addr_ap_ssidno[];
extern const char uci_addr_ap_start_disabled[];
extern const char uci_addr_ap_vlan_bridge[];
extern const char uci_addr_ap_vlan_tagged_interface[];

extern const char uci_addr_mesh_basic_rates[];
extern const char uci_addr_mesh_config_enable[];
extern const char uci_addr_mesh_enable[];
extern const char uci_addr_mesh_key[];

extern const char uci_addr_network_mesh_master[];
extern const char uci_addr_network_mesh_mtu[];
extern const char uci_addr_network_mesh_proto[];

extern const char uci_addr_orphan_enable[];
extern const char uci_addr_orphan_key[];
extern const char uci_addr_orphan_macaddr[];

extern const char uci_addr_orph_conn_bssid[];
extern const char uci_addr_orph_conn_enable[];
extern const char uci_addr_orph_conn_key[];

extern const char uci_addr_batman_bridge_loop_avoidance[];
extern const char uci_addr_batman_gw_stickiness[];
extern const char uci_addr_batman_hop_penalty[];
extern const char uci_addr_batman_protocol[];

extern const char uci_addr_ssid_bridge_to_lan[];
extern const char uci_addr_ssid_custom_dhcp[];
extern const char uci_addr_ssid_dns_intercept[];
extern const char uci_addr_ssid_enable[];
extern const char uci_addr_ssid_ipaddr[];
extern const char uci_addr_ssid_netmask[];
extern const char uci_addr_ssid_vid[];
extern const char uci_addr_ssid_wifi_scheduling[];

extern const char uci_addr_dhcp_ssid_dns_interface[];
extern const char uci_addr_dhcp_ssid_dns_notinterface[];
extern const char uci_addr_dhcp_ssid_dns_port[];
extern const char uci_addr_dhcp_ssid_dns_server[];
extern const char uci_addr_dhcp_ssid_ignore[];
extern const char uci_addr_dhcp_ssid_leasetime[];
extern const char uci_addr_dhcp_ssid_limit[];
extern const char uci_addr_dhcp_ssid_rebind_protection[];
extern const char uci_addr_dhcp_ssid_start[];

extern const char uci_addr_dhcp_relay_interface[];
extern const char uci_addr_dhcp_relay_local_addr[];
extern const char uci_addr_dhcp_relay_server_addr[];

extern const char uci_addr_firewall_datto_lan_block[];
extern const char uci_addr_firewall_smtp_redirect[];
extern const char uci_addr_firewall_ssid_cp_src_dip[];
extern const char uci_addr_firewall_ssid_lan_cp_src_dip[];
extern const char uci_addr_firewall_wired_masq_src[];

extern const char uci_addr_evlog_hostapd_events[];

extern const char uci_addr_fw_core_node_id[];

extern const char uci_addr_prequestd_enable[];
extern const char uci_addr_prequestd_interface[];
extern const char uci_addr_prequestd_interval[];

/* u80211d automatic AP scanning config options */
extern const char uci_addr_u80211d_ap_force[];
extern const char uci_addr_u80211d_country[];
extern const char uci_addr_u80211d_scan_period[];
extern const char uci_addr_u80211d_scan_phy[];

/* u80211d automatic channel survey config options */
extern const char uci_addr_u80211d_survey_dwell_time[];
extern const char uci_addr_u80211d_survey_period[];
extern const char uci_addr_u80211d_survey_phy[];

extern const char uci_addr_ap_mgr_band_steering_enabled[];
extern const char uci_addr_ap_mgr_roaming_enabled[];

#endif /* __DATTO_NET_DATTO_NET_SRC_WIFI_SETTINGS_UCI_ADDRS_H_ */
