// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_plugin.c
 * Adds core plugin to integrate silhouette server into the analysis step.
 */

#include "sil.h"

#define SETDESC(x, y)     rz_config_node_desc(x, y)
#define SETPREFS(x, y, z) SETDESC(rz_config_set(cfg, x, y), z)
#define SETPREFI(x, y, z) SETDESC(rz_config_set_i(cfg, x, y), z)
#define SETPREFB(x, y, z) SETDESC(rz_config_set_b(cfg, x, y), z)

static const RzCmdDescDetailEntry sil_command_group_complete_detail_entries[] = {
	{ .text = "test", .arg_str = NULL, .comment = "Tries to connect, authenticate and prints the response time." },
	{ .text = "share", .arg_str = NULL, .comment = "Tries to share the binary info with the server." },
	{ 0 },
};

static const RzCmdDescDetail sil_command_group_complete_details[] = {
	{ .name = "Options", .entries = sil_command_group_complete_detail_entries },
	{ 0 },
};

static const RzCmdDescHelp sil_command_group_help = {
	.summary = "Rizin silhouette client.",
	.details = sil_command_group_complete_details,
};

static const char *sil_command_choices[] = { "test", "share", NULL };

static const RzCmdDescArg sil_command_args[] = {
	{
		.name = "option",
		.type = RZ_CMD_ARG_TYPE_CHOICES,
		.default_value = "test",
		.choices.choices = sil_command_choices,
	},
	{ 0 },
};

static const RzCmdDescHelp sil_command_help = {
	.summary = "Tests the connection to the silhouette server.",
	.args = sil_command_args,
};

static sil_t *sil_plugin_create(RzCore *core) {
	sil_opt_t opts = {
		.psk = rz_config_get(core->config, RZ_SIL_PSK),
		.address = rz_config_get(core->config, RZ_SIL_HOST),
		.port = rz_config_get(core->config, RZ_SIL_PORT),
		.timeout = rz_config_get_i(core->config, RZ_SIL_TIMEOUT),
#if HAVE_LIB_SSL
		.use_tls = rz_config_get_b(core->config, RZ_SIL_TLS),
#else
		.use_tls = false,
#endif
		.show_msg = rz_config_get_b(core->config, RZ_SIL_SRV_TEXT),
		.can_share = rz_config_get_b(core->config, RZ_SIL_SHARE),
		.can_share_sections = rz_config_get_b(core->config, RZ_SIL_SHARE_SECTIONS),
		.can_share_symbols = rz_config_get_b(core->config, RZ_SIL_SHARE_SYMBOLS),
	};
	return sil_new(&opts);
}

RZ_IPI RzCmdStatus sil_command_handler(RzCore *core, int argc, const char **argv) {
	if (argc < 1) {
		return RZ_CMD_STATUS_ERROR;
	}

	bool result = false;
	sil_t *sil = sil_plugin_create(core);
	if (!sil) {
		return RZ_CMD_STATUS_ERROR;
	}

	if (!strcmp(argv[1], "test")) {
		ut64 start_usec = rz_time_now();
		result = sil_test_connection(sil);
		ut64 end_usec = rz_time_now();
		if (result) {
			float delay = end_usec - start_usec;
			delay /= 1000.f;
			rz_cons_printf("response delay: %.1fms\n", delay);
		}
	} else if (!strcmp(argv[1], "share")) {
		result = sil_share_binary(sil, core);
	} else {
		RZ_LOG_ERROR("sil: invalid argument %s\n", argv[1]);
	}

	sil_free(sil);
	return result ? RZ_CMD_STATUS_OK : RZ_CMD_STATUS_ERROR;
}

RZ_IPI bool sil_plugin_analysis(RzCore *core) {
	bool is_enabled = rz_config_get_b(core->config, RZ_SIL_ENABLE);
	if (!is_enabled) {
		return false;
	}

	sil_t *sil = sil_plugin_create(core);
	if (!sil) {
		return false;
	}

	sil_stats_t stats = { 0 };
	rz_core_notify_begin(core, "Resolving symbols using the silhouette server...");
	bool result = sil_resolve_functions(sil, core, &stats);
	rz_core_notify_done(core, "Applied %u hints and %u symbols using the silhouette server.", stats.hints, stats.symbols);

	sil_free(sil);
	return result;
}

static void sil_setup_evars(RzConfig *cfg) {
	rz_config_lock(cfg, false);
	SETPREFB(RZ_SIL_ENABLE, RZ_SIL_ENABLE_DEFAULT, RZ_SIL_ENABLE_DESCR);
	SETPREFS(RZ_SIL_PSK, RZ_SIL_PSK_DEFAULT, RZ_SIL_PSK_DESCR);
	SETPREFS(RZ_SIL_HOST, RZ_SIL_HOST_DEFAULT, RZ_SIL_HOST_DESCR);
	SETPREFS(RZ_SIL_PORT, RZ_SIL_PORT_DEFAULT, RZ_SIL_PORT_DESCR);
#if HAVE_LIB_SSL
	SETPREFB(RZ_SIL_TLS, RZ_SIL_TLS_DEFAULT, RZ_SIL_TLS_DESCR);
#endif
	SETPREFI(RZ_SIL_TIMEOUT, RZ_SIL_TIMEOUT_DEFAULT, RZ_SIL_TIMEOUT_DESCR);
	SETPREFI(RZ_SIL_PATTERN_SIZE, RZ_SIL_PATTERN_SIZE_DEFAULT, RZ_SIL_PATTERN_SIZE_DESCR);
	SETPREFB(RZ_SIL_SRV_TEXT, RZ_SIL_SRV_TEXT_DEFAULT, RZ_SIL_SRV_TEXT_DESCR);
	SETPREFB(RZ_SIL_SHARE, RZ_SIL_SHARE_DEFAULT, RZ_SIL_SHARE_DESCR);
	SETPREFB(RZ_SIL_SHARE_SECTIONS, RZ_SIL_SHARE_SECTIONS_DEFAULT, RZ_SIL_SHARE_SECTIONS_DESCR);
	SETPREFB(RZ_SIL_SHARE_SYMBOLS, RZ_SIL_SHARE_SYMBOLS_DEFAULT, RZ_SIL_SHARE_SYMBOLS_DESCR);
	rz_config_lock(cfg, true);
}

RZ_IPI bool sil_plugin_init(RzCore *core) {
	RzCmd *rcmd = core->rcmd;
	RzCmdDesc *root_cd = rz_cmd_get_root(rcmd);
	if (!root_cd) {
		rz_warn_if_reached();
		return false;
	}

	sil_setup_evars(core->config);

	RzCmdDesc *sil_cd = rz_cmd_desc_group_new(rcmd, root_cd, "sil", sil_command_handler, &sil_command_help, &sil_command_group_help);
	rz_return_val_if_fail(sil_cd, false);

	return true;
}

RZ_IPI bool sil_plugin_fini(RzCore *core) {
	RzCmd *cmd = core->rcmd;
	RzCmdDesc *desc = rz_cmd_get_desc(cmd, "sil");
	return rz_cmd_desc_remove(cmd, desc);
}

RzCorePlugin rz_core_plugin_sil = {
	.name = "rz_silhouette",
	.author = "deroad",
	.desc = "Rizin Silhouette Client.",
	.license = "LGPL-3.0",
	.init = sil_plugin_init,
	.fini = sil_plugin_fini,
	.analysis = sil_plugin_analysis,
};

#ifdef _MSC_VER
#define RZ_EXPORT __declspec(dllexport)
#else
#define RZ_EXPORT
#endif

#ifndef CORELIB
RZ_EXPORT RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_CORE,
	.data = &rz_core_plugin_sil,
	.version = RZ_VERSION,
};
#endif
