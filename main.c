/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *   Copyright (C) 2020 embedd.ch 
 *   Copyright (C) 2020 Felix Fietkau <nbd@nbd.name> 
 *   Copyright (C) 2020 John Crispin <john@phrozen.org> 
 */

#include <unistd.h>
#include <stdarg.h>
#include <syslog.h>

#include <libubox/blobmsg_json.h>

#include "usteer.h"
#include "event.h"
#include "node.h"

#define DEBUG_FILE_PATH				"/tmp/debug_usteer.log"

struct ubus_context *ubus_ctx;
struct usteer_config config = {};
struct blob_attr *host_info_blob;
uint64_t current_time;
static int dump_time;

LIST_HEAD(node_handlers);

static FILE *gDebug_file = NULL;
static bool gSyslog_open = false;

const char * const event_types[__EVENT_TYPE_MAX] = {
	[EVENT_TYPE_PROBE] = "probe",
	[EVENT_TYPE_AUTH] = "auth",
	[EVENT_TYPE_ASSOC] = "assoc",
};

void log_msg(char *msg)
{
	if (config.syslog)
		syslog(LOG_INFO, "%s\n", msg);
	else
		fprintf(stderr, "%s\n", msg);
}


static void debug_file_close(void)
{
	if (!gDebug_file)
		return;

	fclose(gDebug_file); // Explicitly set to NULL on following line
	gDebug_file = NULL;
}

static bool debug_file_open(const char *debug_file_path)
{
	if (!debug_file_path) {
		fprintf(stderr, "ERROR: debug_file_path is NULL\n");
		return false;
	}

	if (gDebug_file) {
		fprintf(stderr, "WARNING: '%s' is already open for writing.\n", debug_file_path);
		return true;
	}

	gDebug_file = fopen(debug_file_path, "a");

	if (!gDebug_file) {
		fprintf(stderr, "ERROR: failed to open '%s' for writing.\n", debug_file_path);
		return false;
	}

	return true;
}

static inline void debug_init(void)
{
	if (config.is_debug_inited)
		return;

	config.is_debug_inited = true;

	if (!config.file)
		debug_file_close();
	else if (!debug_file_open(DEBUG_FILE_PATH))
		config.file = false;

	if (!config.syslog) {
		if (gSyslog_open)
			closelog();
	} else if (!gSyslog_open) {
		openlog("usteer", 0, LOG_USER);
		gSyslog_open = true;
	}
}

void debug_msg(int level, const char *func, int line, const char *format, ...)
{
	va_list ap;

	if (config.debug_level < level)
		return;

	if (!config.syslog)
		fprintf(stderr, "[%s:%d] ", func, line);

	debug_init();

	va_start(ap, format);

	if (!config.file && !config.syslog) {
		fprintf(stderr, "[%s:%d] ", func, line);
		vfprintf(stderr, format, ap);
	} else {
		if (config.file) {
			vfprintf(gDebug_file, format, ap);
			fflush(gDebug_file);
		}

		if (config.syslog)
			vsyslog(level >= MSG_DEBUG ? LOG_DEBUG : LOG_INFO, format, ap);
	}

	va_end(ap);

}

void debug_msg_cont(int level, const char *format, ...)
{
	va_list ap;

	if (config.debug_level < level)
		return;

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
}

void usteer_init_defaults(void)
{
	memset(&config, 0, sizeof(config));

	config.sta_block_timeout = 30 * 1000;
	config.local_sta_timeout = 120 * 1000;
	config.measurement_report_timeout = 120 * 1000;
	config.local_sta_update = 1 * 1000;
	config.max_retry_band = 5;
	config.max_neighbor_reports = 8;
	config.seen_policy_timeout = 30 * 1000;
	config.band_steering_threshold = 5;
	config.load_balancing_threshold = 0;
	config.remote_update_interval = 1000;
	config.initial_connect_delay = 0;
	config.remote_node_timeout = 10;

	config.steer_reject_timeout = 60000;

	config.band_steering_interval = 120000;
	config.band_steering_min_snr = -60;

	config.link_measurement_interval = 30000;

	config.probe_steering = 0;

	config.roam_kick_delay = 10000;
	config.roam_process_timeout = 5 * 1000;
	config.roam_scan_tries = 3;
	config.roam_scan_timeout = 0;
	config.roam_scan_interval = 10 * 1000;
	config.roam_trigger_interval = 60 * 1000;

	config.min_snr_kick_delay = 5 * 1000;

	config.load_kick_enabled = false;
	config.load_kick_threshold = 75;
	config.load_kick_delay = 10 * 1000;
	config.load_kick_min_clients = 10;
	config.load_kick_reason_code = 5; /* WLAN_REASON_DISASSOC_AP_BUSY */

	config.debug_level = MSG_INFO;
}

void usteer_update_time(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	current_time = (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		" -v:           Increase debug level (repeat for more messages):\n"
		"               1: info messages\n"
		"               2: debug messages\n"
		"               3: verbose debug messages\n"
		"               4: include network messages\n"
		"               5: include extra testing messages\n"
		" -i <name>:    Connect to other instances on interface <name>\n"
		" -s:		Output log messages via syslog instead of stderr\n"
		" -D <n>:	Do not daemonize, wait for <n> seconds and print\n"
		"		remote hosts and nodes\n"
		"\n", prog);
	return 1;
}

static void
usteer_dump_timeout(struct uloop_timeout *t)
{
	struct usteer_remote_host *host;
	struct usteer_remote_node *rn;
	struct blob_buf b = {};
	char *str;
	void *c;

	blob_buf_init(&b, 0);

	c = blobmsg_open_table(&b, "hosts");
	avl_for_each_element(&remote_hosts, host, avl)
		usteer_dump_host(&b, host);
	blobmsg_close_table(&b, c);

	c = blobmsg_open_table(&b, "nodes");
	for_each_remote_node(rn)
		usteer_dump_node(&b, &rn->node);
	blobmsg_close_table(&b, c);

	str = blobmsg_format_json(b.head, true);
	blob_buf_free(&b);

	puts(str);
	free(str);

	uloop_end();
}

int main(int argc, char **argv)
{
	struct uloop_timeout dump_timer;
	int ch;

	usteer_init_defaults();

	while ((ch = getopt(argc, argv, "D:i:sv")) != -1) {
		switch(ch) {
		case 'v':
			config.debug_level++;
			break;
		case 's':
			config.syslog = true;
			break;
		case 'i':
			usteer_interface_add(optarg);
			break;
		case 'D':
			dump_time = atoi(optarg);
			break;
		default:
			return usage(argv[0]);
		}
	}

	config_set_event_log_types(NULL);
	usteer_update_time();
	uloop_init();

	ubus_ctx = ubus_connect(NULL);
	if (!ubus_ctx) {
		fprintf(stderr, "Failed to connect to ubus\n");
		return -1;
	}

	ubus_add_uloop(ubus_ctx);
	if (dump_time) {
		dump_timer.cb = usteer_dump_timeout;
		uloop_timeout_set(&dump_timer, dump_time * 1000);
	} else {
		usteer_ubus_init(ubus_ctx);
		usteer_local_nodes_init(ubus_ctx);
	}
	uloop_run();

	uloop_done();
	debug_file_close();
	return 0;
}
