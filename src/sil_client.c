// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_client.c
 * Implements the tcp protocol to talk to the server.
 *
 * The wire format is a 4-byte big-endian size prefix followed by either the
 * legacy protobuf payload or a SIL2-prefixed Cap'n Proto v2 payload.
 */

#include "sil.h"
#include "sil_helpers.h"
#include "sil_protocol.h"
#include <rz_util/rz_json.h>

#define SIL_RETRY_TIMES (3)
#define SIL_PSEUDOCODE_MAX_FUNCTION_BYTES 2048U
#define SIL_PSEUDOCODE_MAX_TOTAL_BYTES (1024U * 1024U)
#define SIL_PSEUDOCODE_FALLBACK_FUNCTION_BYTES 512U
#define SIL_PSEUDOCODE_FALLBACK_TOTAL_BYTES (128U * 1024U)
#define SIL_PSEUDOCODE_MIN_REMAINING_BYTES 128U
#define SIL_MATERIALIZE_MAX_BB_SIZE 256U
#define SIL_MATERIALIZE_FALLBACK_BB_SIZE 16U
#define SIL_MATERIALIZE_MAX_OPS 32U

typedef struct sil_s {
	char *psk;
	char *address;
	char *port;
	char *decompiler;
	ut32 timeout;
	ut32 keenhash_topk;
	sil_codec_mode_t codec;
	bool use_tls;
	bool show_msg;
	bool can_share;
	bool can_share_sections;
	bool can_share_symbols;
	bool keenhash;
	bool ghidra_probe_done;
	bool ghidra_available;
} sil_t;

typedef struct {
	Signature *message;
	RzAnalysisFunction *function;
} sil_signature_t;

typedef struct {
	RzAnalysis *analysis;
	RzThreadQueue /*<sil_signature_t*>*/ *sigs;
	const RzHashPlugin *blake;
	const char *fcn_prefix;
	const char *arch_name;
	sil_signature_t *end_marker;
	size_t max_size;
	bool stop;
} sil_thread_t;

static SectionHash *sil_section_digest(RzCore *core, RzBinSection *bsect, const RzHashPlugin *blake);
static Signature *sil_function_to_signature(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *arch, const RzHashPlugin *blake, size_t max_pattern);

static void sil_signature_free(sil_signature_t *signature) {
	if (!signature) {
		return;
	}
	proto_signature_free(signature->message);
	free(signature);
}

static sil_signature_t *sil_signature_new(RzAnalysisFunction *function, Signature *message) {
	sil_signature_t *signature = RZ_NEW0(sil_signature_t);
	if (!signature) {
		return NULL;
	}
	signature->function = function;
	signature->message = message;
	return signature;
}

void sil_free(sil_t *sil) {
	if (!sil) {
		return;
	}
	free(sil->psk);
	free(sil->address);
	free(sil->port);
	free(sil->decompiler);
	free(sil);
}

static sil_codec_mode_t sil_codec_parse(const char *value) {
	if (RZ_STR_ISEMPTY(value) || !strcmp(value, "auto")) {
		return SIL_CODEC_AUTO;
	}
	if (!strcmp(value, "protobuf")) {
		return SIL_CODEC_PROTOBUF;
	}
	if (!strcmp(value, "capnp")) {
		return SIL_CODEC_CAPNP;
	}
	RZ_LOG_WARN("silhouette: unknown codec '%s', falling back to auto.\n", value);
	return SIL_CODEC_AUTO;
}

static bool sil_prefers_capnp(const sil_t *sil) {
	return sil && sil->codec != SIL_CODEC_PROTOBUF;
}

static bool sil_can_fallback_to_protobuf(const sil_t *sil) {
	return sil && sil->codec == SIL_CODEC_AUTO;
}

static bool sil_decompiler_enabled(const sil_t *sil) {
	return sil && sil->keenhash && strcmp(sil->decompiler, "off");
}

static bool sil_has_command(RzCore *core, const char *name) {
	if (!core || !core->rcmd || RZ_STR_ISEMPTY(name)) {
		return false;
	}
	return rz_cmd_get_desc(core->rcmd, name) != NULL;
}

static bool sil_is_bb_terminator(const RzAnalysisOp *op) {
	if (!op) {
		return true;
	}
	ut32 type = op->type & RZ_ANALYSIS_OP_TYPE_MASK;
	if (op->type & RZ_ANALYSIS_OP_TYPE_TAIL) {
		return true;
	}
	switch (type) {
	case RZ_ANALYSIS_OP_TYPE_JMP:
	case RZ_ANALYSIS_OP_TYPE_UJMP:
	case RZ_ANALYSIS_OP_TYPE_CJMP:
	case RZ_ANALYSIS_OP_TYPE_RET:
	case RZ_ANALYSIS_OP_TYPE_CRET:
	case RZ_ANALYSIS_OP_TYPE_TRAP:
	case RZ_ANALYSIS_OP_TYPE_ILL:
	case RZ_ANALYSIS_OP_TYPE_SWI:
	case RZ_ANALYSIS_OP_TYPE_CSWI:
		return true;
	default:
		return false;
	}
}

static RzBinSymbol *sil_find_bin_symbol(RzBinFile *bf, const char *name, ut64 vaddr) {
	if (!bf || !bf->o || !bf->o->symbols || RZ_STR_ISEMPTY(name)) {
		return NULL;
	}
	void **it = NULL;
	rz_pvector_foreach (bf->o->symbols, it) {
		RzBinSymbol *symbol = (RzBinSymbol *)*it;
		if (!symbol || symbol->vaddr != vaddr || RZ_STR_ISEMPTY(symbol->name)) {
			continue;
		}
		if (!strcmp(symbol->name, name)) {
			return symbol;
		}
	}
	return NULL;
}

static void sil_upsert_bin_symbol(RzCore *core, const char *name, ut64 addr, ut64 size) {
	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->symbols || RZ_STR_ISEMPTY(name)) {
		return;
	}

	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	size_t offset = !strncmp(name, "sym.", strlen("sym.")) ? strlen("sym.") : 0;
	ut64 paddr = is_va ? rz_bin_object_v2p(bf->o, addr) : addr;
	RzBinSymbol *existing = sil_find_bin_symbol(bf, name + offset, addr);
	if (existing) {
		existing->size = size;
		return;
	}

	RzBinSymbol *symbol = rz_bin_symbol_new(name + offset, paddr, addr);
	if (!symbol) {
		RZ_LOG_ERROR("silhouette: failed to allocate bin symbol for '%s'\n", name);
		return;
	}

	RzBinSymbol *last = (RzBinSymbol *)rz_pvector_tail(bf->o->symbols);
	if (last) {
		symbol->ordinal = last->ordinal + 1;
	}
	symbol->size = size;
	symbol->bind = RZ_BIN_BIND_GLOBAL_STR;
	symbol->type = RZ_BIN_TYPE_FUNC_STR;
	if (!rz_pvector_push(bf->o->symbols, symbol)) {
		rz_bin_symbol_free(symbol);
	}
}

static ut32 sil_estimate_materialized_bb_size(RzCore *core, ut64 address, ut32 suggested_size, ut64 *jump, ut64 *fail) {
	ut64 limit = suggested_size > 0 ? suggested_size : SIL_MATERIALIZE_MAX_BB_SIZE;
	limit = RZ_MIN(limit, (ut64)SIL_MATERIALIZE_MAX_BB_SIZE);
	ut32 total = 0;

	if (jump) {
		*jump = UT64_MAX;
	}
	if (fail) {
		*fail = UT64_MAX;
	}

	for (ut32 i = 0; i < SIL_MATERIALIZE_MAX_OPS && total < limit; i++) {
		ut64 current = address + total;
		if (total > 0) {
			RzAnalysisFunction *next_func = rz_analysis_get_function_at(core->analysis, current);
			if ((next_func && next_func->addr == current) || rz_flag_get_i(core->flags, current)) {
				break;
			}
		}

		RzAnalysisOp *op = rz_core_op_analysis(core, current, RZ_ANALYSIS_OP_MASK_BASIC | RZ_ANALYSIS_OP_MASK_HINT);
		if (!op || op->size < 1) {
			rz_analysis_op_free(op);
			break;
		}

		ut32 next_total = total + (ut32)op->size;
		if (next_total > limit && total > 0) {
			rz_analysis_op_free(op);
			break;
		}
		total = next_total;
		if (jump && op->jump != UT64_MAX) {
			*jump = op->jump;
		}
		if (fail && op->fail != UT64_MAX) {
			*fail = op->fail;
		}
		bool stop = sil_is_bb_terminator(op);
		rz_analysis_op_free(op);
		if (stop) {
			break;
		}
	}

	if (total < 1) {
		total = suggested_size > 0 ? suggested_size : SIL_MATERIALIZE_FALLBACK_BB_SIZE;
		total = RZ_MIN(total, (ut32)SIL_MATERIALIZE_MAX_BB_SIZE);
	}
	return total;
}

static bool sil_ghidra_available(sil_t *sil, RzCore *core) {
	if (!sil || !core) {
		return false;
	}
	if (!sil->ghidra_probe_done) {
		sil->ghidra_available = sil_has_command(core, "pdg") || sil_has_command(core, "pdgj");
		sil->ghidra_probe_done = true;
	}
	return sil->ghidra_available;
}

static char *sil_strdup_n(const char *text, size_t len) {
	char *copy = malloc(len + 1);
	if (!copy) {
		return NULL;
	}
	memcpy(copy, text, len);
	copy[len] = '\0';
	return copy;
}

static ut32 sil_timeout_to_socket_seconds(ut32 timeout_ms) {
	if (!timeout_ms) {
		return 0;
	}
	return (timeout_ms + 999) / 1000;
}

sil_t *sil_new(sil_opt_t *opts) {
	rz_return_val_if_fail(opts, NULL);

	sil_t *sil = RZ_NEW0(sil_t);
	if (!sil) {
		return NULL;
	}

	sil->psk = strdup(opts->psk);
	sil->address = strdup(opts->address);
	sil->port = strdup(opts->port);
	sil->decompiler = strdup(RZ_STR_ISEMPTY(opts->decompiler) ? "off" : opts->decompiler);
	sil->timeout = opts->timeout;
	sil->codec = sil_codec_parse(opts->codec);
	sil->keenhash_topk = opts->keenhash_topk;
	sil->use_tls = opts->use_tls;
	sil->show_msg = opts->show_msg;
	sil->can_share = opts->can_share;
	sil->can_share_sections = opts->can_share_sections;
	sil->can_share_symbols = opts->can_share_symbols;
	sil->keenhash = opts->keenhash;

	if (RZ_STR_ISEMPTY(sil->address)) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory or empty string (address)\n");
		goto fail;
	} else if (RZ_STR_ISEMPTY(sil->port)) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory or empty string (port)\n");
		goto fail;
	} else if (RZ_STR_ISEMPTY(sil->psk)) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory or empty string (psk)\n");
		goto fail;
	} else if (!sil->decompiler) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory (decompiler)\n");
		goto fail;
	}

	return sil;

fail:
	sil_free(sil);
	return NULL;
}

static RzSocket *sil_socket_new(sil_t *sil) {
	RzSocket *socket = rz_socket_new(sil->use_tls);
	if (!socket) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory (socket)\n");
		return NULL;
	}

	if (!rz_socket_connect_tcp(socket, sil->address, sil->port, sil_timeout_to_socket_seconds(sil->timeout))) {
		RZ_LOG_ERROR("silhouette: failed to connect to %s at port %s (%s)\n", sil->address, sil->port, sil->use_tls ? "secure" : "insecure");
		rz_socket_free(socket);
		return NULL;
	}
	return socket;
}

static bool sil_handle_fail_status(Status status) {
	switch (status) {
	case STATUS__INTERNAL_ERROR:
		RZ_LOG_ERROR("silhouette: internal server error.\n");
		return false;
	case STATUS__CLIENT_BAD_PRE_SHARED_KEY:
		RZ_LOG_ERROR("silhouette: server did not accept the current psk.\n");
		return false;
	case STATUS__CLIENT_NOT_AUTHORIZED:
		RZ_LOG_ERROR("silhouette: client was not authorized.\n");
		return false;
	case STATUS__VERSION_MISMATCH:
		RZ_LOG_ERROR("silhouette: the installed plugin is too old.\n");
		return false;
	default:
		RZ_LOG_ERROR("silhouette: could not understand the respose from the server %u.\n", status);
		return false;
	}
}

static bool sil_handle_fail_status_v2(enum StatusV2 status, const sil_v2_response_t *response) {
	const char *message = response && response->which == ResponseV2_message ? response->text : NULL;
	switch (status) {
	case StatusV2_internalError:
		RZ_LOG_ERROR("silhouette: internal server error%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	case StatusV2_clientBadPreSharedKey:
		RZ_LOG_ERROR("silhouette: server did not accept the current psk%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	case StatusV2_clientNotAuthorized:
		RZ_LOG_ERROR("silhouette: client was not authorized%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	case StatusV2_versionMismatch:
		RZ_LOG_ERROR("silhouette: the installed plugin is too old%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	default:
		RZ_LOG_ERROR("silhouette: could not understand the capnp response from the server %u.\n", status);
		return false;
	}
}

static bool sil_v2_can_fallback_silently(const sil_t *sil, enum StatusV2 status, const sil_v2_response_t *response) {
	const char *message = response && response->which == ResponseV2_message ? response->text : NULL;
	if (!sil_can_fallback_to_protobuf(sil)) {
		return false;
	}
	if (status == StatusV2_versionMismatch) {
		return true;
	}
	return status == StatusV2_clientNotAuthorized &&
		RZ_STR_ISNOTEMPTY(message) &&
		strstr(message, "capnp v2 requires TLS");
}

static void sil_show_server_info(const sil_t *sil, const sil_server_info_t *info) {
	if (!sil || !sil->show_msg || !info) {
		return;
	}
	rz_cons_printf("silhouette server: protocol %u-%u, keenhash=%s, tls=%s, model=%s, index=%s\n",
		info->min_version,
		info->max_version,
		info->keenhash_enabled ? "on" : "off",
		info->tls_required ? "required" : "optional",
		RZ_STR_ISNOTEMPTY(info->model_version) ? info->model_version : "-",
		RZ_STR_ISNOTEMPTY(info->index_version) ? info->index_version : "-");
	rz_cons_flush();
}

static void sil_measure_latency_add(ut64 *elapsed_usec, ut64 started_usec) {
	if (elapsed_usec) {
		*elapsed_usec += rz_time_now() - started_usec;
	}
}

#define sil_retry_n_times(n_times, send, recv, fail) \
	do { \
		bool sil_retry_ok = false; \
		for (int sil_retry_i = 0; sil_retry_i <= (n_times); ++sil_retry_i) { \
			(send); \
			if (recv) { \
				sil_retry_ok = true; \
				break; \
			} \
		} \
		if (!sil_retry_ok) { \
			fail \
		} \
	} while (0)

static bool sil_ping_handle_v1(sil_t *sil, ut64 *elapsed_usec) {
	bool result = true;
	Message *message = NULL;
	Status status = STATUS__INTERNAL_ERROR;
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	ut64 started_usec = rz_time_now();
	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_ping_send(socket, sil->psk),
		sil_protocol_response_recv(socket, &status, (void **)&message),
		{
			sil_measure_latency_add(elapsed_usec, started_usec);
			result = false;
			goto fail;
		});
	sil_measure_latency_add(elapsed_usec, started_usec);

	if (status != STATUS__MESSAGE) {
		result = sil_handle_fail_status(status);
	} else if (message && sil->show_msg &&
		!RZ_STR_ISEMPTY(message->text)) {
		rz_cons_printf("%s\n", message->text);
		rz_cons_flush();
	}

fail:
	rz_socket_close(socket);
	rz_socket_free(socket);
	message__free_unpacked(message, NULL);
	return result;
}

static bool sil_ping_handle_v2(sil_t *sil, ut64 *elapsed_usec) {
	bool result = true;
	sil_v2_response_t response = { 0 };
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	ut64 started_usec = rz_time_now();
	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_ping_v2_send(socket, sil->psk),
		sil_protocol_response_v2_recv(socket, &response),
		{
			sil_measure_latency_add(elapsed_usec, started_usec);
			result = false;
			goto fail;
		});
	sil_measure_latency_add(elapsed_usec, started_usec);
	sil_capnp_debug_dump_response("ping", &response);

	if (response.status != StatusV2_serverInfo) {
		if (sil_v2_can_fallback_silently(sil, response.status, &response)) {
			result = false;
			goto fail;
		}
		result = sil_handle_fail_status_v2(response.status, &response);
	} else {
		sil_show_server_info(sil, &response.server_info);
	}

fail:
	rz_socket_close(socket);
	rz_socket_free(socket);
	sil_capnp_response_fini(&response);
	return result;
}

static bool sil_ping_handle(sil_t *sil, ut64 *elapsed_usec) {
	if (elapsed_usec) {
		*elapsed_usec = 0;
	}
	if (!sil_prefers_capnp(sil)) {
		return sil_ping_handle_v1(sil, elapsed_usec);
	}
	if (sil_ping_handle_v2(sil, elapsed_usec)) {
		return true;
	}
	if (sil_can_fallback_to_protobuf(sil)) {
		RZ_LOG_INFO("silhouette: falling back to protobuf ping.\n");
		return sil_ping_handle_v1(sil, elapsed_usec);
	}
	return false;
}

static void sil_apply_match_hints(RzCore *core, const MatchHints *matches, sil_stats_t *stats) {
	RzAnalysisFunction *func = NULL;
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	if (!bo) {
		RZ_LOG_ERROR("silhouette: failed to get bin object\n");
		return;
	}

	for (size_t i = 0; i < matches->n_hints; ++i) {
		const Hint *hint = matches->hints[i];
		if (!hint) {
			continue;
		}
		ut64 address = is_va ? rz_bin_object_p2v(bo, hint->offset) : hint->offset;

		rz_core_analysis_function_add(core, NULL, address, false);

		func = rz_analysis_get_function_at(core->analysis, address);
		if (!func) {
			// something wrong happened here.
			// we skip applying the matches.
			continue;
		}

		if (hint->bits > 0) {
			func->bits = hint->bits;
		}
		stats->hints++;
		RZ_LOG_DEBUG("silhouette: hinted function %s\n", func->name);
	}
}

static bool sil_binary_handle(sil_t *sil, Binary *binary, RzCore *core, sil_stats_t *stats) {
	bool result = true;
	MatchHints *message = NULL;
	Status status = STATUS__INTERNAL_ERROR;
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_binary_send(socket, sil->psk, binary),
		sil_protocol_response_recv(socket, &status, (void **)&message),
		{
			result = false;
			goto fail;
		});

	if (status != STATUS__HINTS) {
		result = sil_handle_fail_status(status);
	} else if (message) {
		sil_apply_match_hints(core, message, stats);
	}

fail:
	rz_socket_close(socket);
	rz_socket_free(socket);
	match_hints__free_unpacked(message, NULL);
	return result;
}

static bool try_rename_function(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *name) {
	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		// do not rename if is a symbol but check if
		// another function has the same name
		return ht_sp_find(analysis->ht_name_fun, name, NULL) == NULL;
	}
	return rz_analysis_function_rename(fcn, name);
}

static char *propose_function_name(RzAnalysis *analysis, RzAnalysisFunction *fcn, const Symbol *symbol) {
	char *name = rz_str_newf("%s", symbol->name);
	if (!name) {
		RZ_LOG_ERROR("silhouette: cannot allocate string buffer for name '%s'\n", symbol->name);
		return NULL;
	}

	ut32 name_index = 0;
	// verify that the name is unique
	while (!try_rename_function(analysis, fcn, name)) {
		free(name);
		name = rz_str_newf("%s_%u", symbol->name, name_index);
		name_index++;
		if (!name) {
			RZ_LOG_ERROR("silhouette: cannot allocate string buffer for name '%s'\n", symbol->name);
			return NULL;
		}
	}

	return name;
}

static void add_new_symbol(RzCore *core, const char *name, RzAnalysisFunction *fcn) {
	RzAnalysis *analysis = core->analysis;
	const bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	const char *prefix = rz_config_get(core->config, RZ_ANALYSIS_FCN_PREFIX);
	if (RZ_STR_ISEMPTY(prefix)) {
		prefix = "fcn";
	}

	// remove old flag
	char *old_prefix = rz_str_newf("%s.", prefix);
	RzFlagItem *fit = analysis->flb.get_at_by_spaces(analysis->flb.f, fcn->addr, old_prefix, "data.", NULL);
	free(old_prefix);

	ut64 size = fit->size;
	if (fit) {
		analysis->flb.unset(analysis->flb.f, fit);
	}

	// set new flag
	analysis->flb.set(analysis->flb.f, name, fcn->addr, size);

	(void)is_va;
	sil_upsert_bin_symbol(core, name, fcn->addr, size);
}

static void add_named_flag_at(RzCore *core, const char *name, ut64 addr, ut64 size) {
	if (!core || RZ_STR_ISEMPTY(name)) {
		return;
	}

	core->analysis->flb.set(core->analysis->flb.f, name, addr, size);

	sil_upsert_bin_symbol(core, name, addr, size);
}

static ut64 sil_offset_to_addr(RzCore *core, ut64 offset) {
	if (!core || !offset) {
		return offset;
	}
	if (!rz_config_get_b(core->config, RZ_IO_VA)) {
		return offset;
	}
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	return bo ? rz_bin_object_p2v(bo, offset) : offset;
}

static RzAnalysisFunction *sil_materialize_function(RzCore *core, ut64 address, ut32 size) {
	RzAnalysisFunction *func = rz_analysis_get_function_at(core->analysis, address);
	if (func && func->addr == address) {
		return func;
	}

	if (!func) {
		rz_core_analysis_function_add(core, NULL, address, false);
		func = rz_analysis_get_function_at(core->analysis, address);
		if (func && func->addr == address) {
			return func;
		}
	}

	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	ut32 bb_size = sil_estimate_materialized_bb_size(core, address, size, &jump, &fail);
	char *tmp_name = rz_str_newf("fcn.sil.%" PFMT64x, address);
	if (!tmp_name) {
		return NULL;
	}
	rz_core_cmdf(core, "af+ %s @ 0x%" PFMT64x, tmp_name, address);
	if (jump != UT64_MAX && fail != UT64_MAX) {
		rz_core_cmdf(core, "afb+ 0x%" PFMT64x " 0x%" PFMT64x " %u 0x%" PFMT64x " 0x%" PFMT64x, address, address, (unsigned int)bb_size, jump, fail);
	} else if (jump != UT64_MAX) {
		rz_core_cmdf(core, "afb+ 0x%" PFMT64x " 0x%" PFMT64x " %u 0x%" PFMT64x, address, address, (unsigned int)bb_size, jump);
	} else {
		rz_core_cmdf(core, "afb+ 0x%" PFMT64x " 0x%" PFMT64x " %u", address, address, (unsigned int)bb_size);
	}
	free(tmp_name);
	func = rz_analysis_get_function_at(core->analysis, address);
	return func && func->addr == address ? func : NULL;
}

static void sil_apply_symbol(RzCore *core, RzAnalysisFunction *fcn, Symbol *symbol, sil_stats_t *stats) {
	char *name = NULL;
	if (!symbol) {
		return;
	}

	RZ_LOG_INFO("silhouette: '%s' matches to '%s'\n", fcn->name, symbol->name);

	// filter name
	rz_name_filter(symbol->name, -1, true);

	// create new flag name
	name = propose_function_name(core->analysis, fcn, symbol);
	if (!name) {
		RZ_LOG_ERROR("silhouette: cannot allocate string buffer for name '%s'\n", symbol->name);
		goto fail;
	}

	// set new symbol
	add_new_symbol(core, name, fcn);
	RZ_LOG_DEBUG("silhouette: renamed to %s\n", name);

	// apply function signature
	if (!RZ_STR_ISEMPTY(symbol->signature)) {
		// strip any `sym.` and remove `.` from the signature.
		symbol->signature = rz_str_replace(symbol->signature, "sym.", "", 0);
		rz_str_replace_ch(symbol->signature, '.', '_', 1);
		if (!rz_analysis_function_set_type_str(core->analysis, fcn, symbol->signature)) {
			RZ_LOG_ERROR("silhouette: failed to set signature '%s' for '%s'.\n", symbol->signature, name);
		}
	}

	// apply function calling convention
	if (!RZ_STR_ISEMPTY(symbol->callconv)) {
		const char *orig = fcn->cc;
		fcn->cc = rz_str_constpool_get(&core->analysis->constpool, symbol->callconv);
		if (!fcn->cc) {
			fcn->cc = orig;
			RZ_LOG_ERROR("silhouette: failed to get calling convention for '%s'.\n", name);
		}
	}
	stats->symbols++;

fail:
	free(name);
}

static bool sil_should_query_function_name(const char *name, const char *prefix) {
	(void)prefix;
	if (RZ_STR_ISEMPTY(name)) {
		return false;
	}
	return strncmp(name, "sym.imp.", strlen("sym.imp."));
}

static ut32 sil_count_lines(const char *text) {
	if (RZ_STR_ISEMPTY(text)) {
		return 0;
	}
	ut32 lines = 1;
	for (const char *ptr = text; *ptr; ptr++) {
		if (*ptr == '\n') {
			lines++;
		}
	}
	return lines;
}

static ut32 sil_count_statements(const char *text) {
	if (RZ_STR_ISEMPTY(text)) {
		return 0;
	}
	ut32 statements = 0;
	for (const char *ptr = text; *ptr; ptr++) {
		if (*ptr == ';') {
			statements++;
		}
	}
	return statements;
}

static char *sil_normalize_pseudocode_text(char *text, ut32 *loc, ut32 *nos) {
	if (!text) {
		return NULL;
	}
	rz_str_trim(text);
	if (RZ_STR_ISEMPTY(text)) {
		free(text);
		return NULL;
	}
	if (loc) {
		*loc = sil_count_lines(text);
	}
	if (nos) {
		*nos = sil_count_statements(text);
	}
	return text;
}

static char *sil_extract_ghidra_pseudocode(RzCore *core, RzAnalysisFunction *func, ut32 *loc, ut32 *nos) {
	char *json = rz_core_cmd_strf(core, "pdgj @ 0x%" PFMT64x, func->addr);
	if (!json || (*json != '{' && *json != '[')) {
		free(json);
		return NULL;
	}

	RzJson *root = rz_json_parse(json);
	if (!root) {
		free(json);
		return NULL;
	}

	const RzJson *node = root;
	if (root->type == RZ_JSON_ARRAY) {
		node = rz_json_item(root, 0);
	}

	const RzJson *code = node ? rz_json_get(node, "code") : NULL;
	if (!code) {
		code = node ? rz_json_get(node, "pseudocode") : NULL;
	}
	if (!code || code->type != RZ_JSON_STRING || RZ_STR_ISEMPTY(code->str_value)) {
		rz_json_free(root);
		free(json);
		return NULL;
	}

	char *text = strdup(code->str_value);
	rz_json_free(root);
	free(json);
	return sil_normalize_pseudocode_text(text, loc, nos);
}

static char *sil_extract_asm_pseudo(RzCore *core, RzAnalysisFunction *func, ut32 *loc, ut32 *nos) {
	if (!core || !func) {
		return NULL;
	}

	bool old_pseudo = rz_config_get_b(core->config, "asm.pseudo");
	char *json = NULL;
	RzJson *root = NULL;
	RzStrBuf *buf = NULL;
	char *text = NULL;
	rz_config_set_b(core->config, "asm.pseudo", true);
	json = rz_core_cmd_strf(core, "pdfj @ 0x%" PFMT64x, func->addr);
	rz_config_set_b(core->config, "asm.pseudo", old_pseudo);
	if (!json || *json != '{') {
		free(json);
		return NULL;
	}

	root = rz_json_parse(json);
	if (!root || root->type != RZ_JSON_OBJECT) {
		rz_json_free(root);
		free(json);
		return NULL;
	}

	const RzJson *ops = rz_json_get(root, "ops");
	if (!ops || ops->type != RZ_JSON_ARRAY) {
		rz_json_free(root);
		free(json);
		return NULL;
	}

	buf = rz_strbuf_new("");
	if (!buf) {
		rz_json_free(root);
		free(json);
		return NULL;
	}

	for (size_t i = 0;; i++) {
		const RzJson *item = rz_json_item(ops, i);
		if (!item) {
			break;
		}
		const RzJson *opcode = item ? rz_json_get(item, "opcode") : NULL;
		const RzJson *disasm = item ? rz_json_get(item, "disasm") : NULL;
		const char *line = NULL;
		if (opcode && opcode->type == RZ_JSON_STRING && RZ_STR_ISNOTEMPTY(opcode->str_value)) {
			line = opcode->str_value;
		} else if (disasm && disasm->type == RZ_JSON_STRING && RZ_STR_ISNOTEMPTY(disasm->str_value)) {
			line = disasm->str_value;
		}
		if (RZ_STR_ISEMPTY(line)) {
			continue;
		}
		rz_strbuf_append(buf, line);
		rz_strbuf_append(buf, "\n");
	}

	text = rz_strbuf_drain(buf);
	rz_json_free(root);
	free(json);
	return sil_normalize_pseudocode_text(text, loc, nos);
}

static char *sil_extract_pseudocode(RzCore *core, sil_t *sil, RzAnalysisFunction *func, ut32 *loc, ut32 *nos, const char **source) {
	if (source) {
		*source = "none";
	}
	if (!sil_decompiler_enabled(sil) || !core || !func) {
		return NULL;
	}

	char *text = NULL;
	if (!RZ_STR_ISEMPTY(sil->decompiler) && !strcmp(sil->decompiler, "rz-ghidra") && sil_ghidra_available(sil, core)) {
		text = sil_extract_ghidra_pseudocode(core, func, loc, nos);
		if (text) {
			if (source) {
				*source = "ghidra";
			}
			return text;
		}
	}

	text = sil_extract_asm_pseudo(core, func, loc, nos);
	if (text && source) {
		*source = "pseudo";
	}
	return text;
}

static char *sil_trim_pseudocode_budget(char *text, ut32 *loc, ut32 *nos, size_t *remaining_budget, const char **source) {
	if (!text) {
		return NULL;
	}

	size_t budget = remaining_budget ? *remaining_budget : SIL_PSEUDOCODE_MAX_TOTAL_BYTES;
	if (budget < SIL_PSEUDOCODE_MIN_REMAINING_BYTES) {
		free(text);
		if (loc) {
			*loc = 0;
		}
		if (nos) {
			*nos = 0;
		}
		if (source) {
			*source = "none";
		}
		return NULL;
	}

	size_t function_limit = (source && *source && !strcmp(*source, "pseudo")) ?
		(size_t)SIL_PSEUDOCODE_FALLBACK_FUNCTION_BYTES :
		(size_t)SIL_PSEUDOCODE_MAX_FUNCTION_BYTES;
	size_t limit = RZ_MIN(function_limit, budget);
	size_t length = strlen(text);
	if (length > limit) {
		char *trimmed = sil_strdup_n(text, limit);
		free(text);
		if (!trimmed) {
			if (source) {
				*source = "none";
			}
			return NULL;
		}
		text = sil_normalize_pseudocode_text(trimmed, loc, nos);
		if (!text) {
			if (source) {
				*source = "none";
			}
			return NULL;
		}
		length = strlen(text);
	}

	if (remaining_budget) {
		*remaining_budget = budget > length ? budget - length : 0;
	}
	return text;
}

static size_t sil_initial_pseudocode_budget(RzCore *core, sil_t *sil) {
	if (!sil_decompiler_enabled(sil)) {
		return 0;
	}
	if (!RZ_STR_ISEMPTY(sil->decompiler) && !strcmp(sil->decompiler, "rz-ghidra") && sil_ghidra_available(sil, core)) {
		return SIL_PSEUDOCODE_MAX_TOTAL_BYTES;
	}
	return SIL_PSEUDOCODE_FALLBACK_TOTAL_BYTES;
}

static bool sil_program_bundle_alloc(sil_program_bundle_t *bundle, size_t sections, size_t functions) {
	memset(bundle, 0, sizeof(*bundle));
	bundle->sections = sections > 0 ? calloc(sizeof(sil_section_v2_t), sections) : NULL;
	bundle->functions = functions > 0 ? calloc(sizeof(sil_function_v2_t), functions) : NULL;
	return (sections == 0 || bundle->sections) && (functions == 0 || bundle->functions);
}

static ut8 *sil_memdup_or_null(const ut8 *data, size_t size) {
	if (!data || size < 1) {
		return NULL;
	}
	ut8 *dup = malloc(size);
	if (!dup) {
		return NULL;
	}
	memcpy(dup, data, size);
	return dup;
}

static bool sil_copy_section_to_v2(sil_section_v2_t *dst, const RzBinSection *section, SectionHash *hash) {
	if (!dst) {
		return false;
	}
	dst->name = section && section->name ? strdup(section->name) : NULL;
	if (section && section->name && !dst->name) {
		return false;
	}
	dst->size = hash ? hash->size : 0;
	dst->paddr = hash ? hash->paddr : 0;
	dst->digest_size = hash ? hash->digest.len : 0;
	if (dst->digest_size > 0) {
		dst->digest = sil_memdup_or_null(hash->digest.data, dst->digest_size);
		if (!dst->digest) {
			return false;
		}
	}
	return true;
}

static bool sil_copy_signature_to_v2(sil_function_v2_t *dst, Signature *signature) {
	if (!dst || !signature) {
		return false;
	}
	dst->bits = signature->bits;
	dst->length = signature->length;
	dst->arch = signature->arch ? strdup(signature->arch) : NULL;
	if (signature->arch && !dst->arch) {
		return false;
	}
	dst->digest_size = signature->digest.len;
	if (dst->digest_size > 0) {
		dst->digest = sil_memdup_or_null(signature->digest.data, dst->digest_size);
		if (!dst->digest) {
			return false;
		}
	}
	return true;
}

static bool sil_collect_exec_sections(RzCore *core, sil_program_bundle_t *bundle, const RzHashPlugin *blake) {
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	if (!bo) {
		return false;
	}
	const RzPVector *sections = rz_bin_object_get_sections_all(bo);
	size_t index = 0;
	void **it;
	rz_pvector_foreach (sections, it) {
		RzBinSection *section = (RzBinSection *)*it;
		if (!(section->perm & RZ_PERM_X)) {
			continue;
		}
		SectionHash *hash = sil_section_digest(core, section, blake);
		if (!hash) {
			return false;
		}
		if (!sil_copy_section_to_v2(&bundle->sections[index], section, hash)) {
			proto_section_hash_free(hash);
			return false;
		}
		index++;
		proto_section_hash_free(hash);
	}
	bundle->n_sections = index;
	return true;
}

static bool sil_build_resolve_program_bundle(sil_t *sil, RzCore *core, sil_program_bundle_t *bundle) {
	const RzHashPlugin *blake = rz_hash_plugin_by_name(core->hash, "blake3");
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	RzAnalysis *analysis = core->analysis;
	const char *arch = rz_config_get(core->config, RZ_ASM_ARCH);
	const char *prefix = rz_config_get(core->config, RZ_ANALYSIS_FCN_PREFIX);
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	size_t max_size = rz_config_get_i(core->config, RZ_SIL_PATTERN_SIZE);
	size_t pseudocode_budget = sil_initial_pseudocode_budget(core, sil);
	size_t n_functions = 0;
	RzListIter *it = NULL;
	RzAnalysisFunction *func = NULL;

	if (!bo || !analysis || !blake) {
		return false;
	}
	if (RZ_STR_ISEMPTY(prefix)) {
		prefix = "fcn";
	}

	rz_list_foreach (analysis->fcns, it, func) {
		if (sil_should_query_function_name(func->name, prefix)) {
			n_functions++;
		}
	}

	const RzPVector *sections = rz_bin_object_get_sections_all(bo);
	size_t n_sections = 0;
	void **vit;
	rz_pvector_foreach (sections, vit) {
		RzBinSection *section = (RzBinSection *)*vit;
		if (section->perm & RZ_PERM_X) {
			n_sections++;
		}
	}

	if (!sil_program_bundle_alloc(bundle, n_sections, n_functions)) {
		return false;
	}

	bundle->binary_type = bo->plugin ? sil_to_lower_dup(bo->plugin->name, "any") : strdup("any");
	bundle->os = bo->info ? sil_to_lower_dup(bo->info->os, "any") : strdup("any");
	bundle->arch = sil_to_lower_dup(arch, "any");
	if (!bundle->binary_type || !bundle->os || !bundle->arch) {
		return false;
	}
	bundle->bits = rz_config_get_i(core->config, RZ_ASM_BITS);
	bundle->topk = sil->keenhash_topk;

	if (!sil_collect_exec_sections(core, bundle, blake)) {
		return false;
	}

	size_t index = 0;
	rz_list_foreach (analysis->fcns, it, func) {
		if (!sil_should_query_function_name(func->name, prefix)) {
			continue;
		}

		sil_function_v2_t *dst = &bundle->functions[index];
		RzBinSection *section = rz_bin_get_section_at(bo, func->addr, rz_config_get_b(core->config, RZ_IO_VA));
		Signature *signature = sil_function_to_signature(analysis, func, arch, blake, max_size);
		if (!signature) {
			continue;
		}

		dst->addr = func->addr;
		dst->size = rz_analysis_function_linear_size(func);
		dst->name = func->name ? strdup(func->name) : NULL;
		dst->signature = rz_analysis_function_get_signature(func);
		dst->callconv = func->cc ? strdup(func->cc) : NULL;
		if ((func->name && !dst->name) || (func->cc && !dst->callconv) || !sil_copy_signature_to_v2(dst, signature)) {
			proto_signature_free(signature);
			return false;
		}

		if (section) {
			ut64 section_addr = is_va ? section->vaddr : section->paddr;
			dst->section_name = section->name ? strdup(section->name) : NULL;
			if (section->name && !dst->section_name) {
				proto_signature_free(signature);
				return false;
			}
			dst->section_paddr = section->paddr;
			if (func->addr >= section_addr) {
				dst->section_offset = func->addr - section_addr;
			}
		}
		const char *pseudocode_source = "none";
		if (pseudocode_budget >= SIL_PSEUDOCODE_MIN_REMAINING_BYTES) {
			dst->pseudocode = sil_extract_pseudocode(core, sil, func, &dst->loc, &dst->nos, &pseudocode_source);
			dst->pseudocode = sil_trim_pseudocode_budget(dst->pseudocode, &dst->loc, &dst->nos, &pseudocode_budget, &pseudocode_source);
		}
		dst->pseudocode_source = strdup(pseudocode_source);
		if (!dst->pseudocode_source) {
			proto_signature_free(signature);
			return false;
		}
		index++;
		proto_signature_free(signature);
	}

	bundle->n_functions = index;
	return true;
}

static bool sil_build_share_program_bundle(sil_t *sil, RzCore *core, sil_program_bundle_t *bundle) {
	const RzHashPlugin *blake = rz_hash_plugin_by_name(core->hash, "blake3");
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	RzAnalysis *analysis = core->analysis;
	const char *arch = rz_config_get(core->config, RZ_ASM_ARCH);
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	size_t max_size = rz_config_get_i(core->config, RZ_SIL_PATTERN_SIZE);
	size_t pseudocode_budget = sil_initial_pseudocode_budget(core, sil);
	size_t n_functions = 0;
	void **it = NULL;

	if (!bo || !analysis || !bo->symbols || !blake) {
		return false;
	}

	rz_pvector_foreach (bo->symbols, it) {
		RzBinSymbol *symbol = (RzBinSymbol *)*it;
		if (symbol && !symbol->is_imported && rz_analysis_get_function_at(analysis, symbol->vaddr)) {
			n_functions++;
		}
	}

	const RzPVector *sections = rz_bin_object_get_sections_all(bo);
	size_t n_sections = 0;
	rz_pvector_foreach (sections, it) {
		RzBinSection *section = (RzBinSection *)*it;
		if (section->perm & RZ_PERM_X) {
			n_sections++;
		}
	}

	if (!sil_program_bundle_alloc(bundle, n_sections, n_functions)) {
		return false;
	}

	bundle->binary_type = bo->plugin ? sil_to_lower_dup(bo->plugin->name, "any") : strdup("any");
	bundle->os = bo->info ? sil_to_lower_dup(bo->info->os, "any") : strdup("any");
	bundle->arch = sil_to_lower_dup(arch, "any");
	if (!bundle->binary_type || !bundle->os || !bundle->arch) {
		return false;
	}
	bundle->bits = rz_config_get_i(core->config, RZ_ASM_BITS);
	bundle->topk = sil->keenhash_topk;

	if (!sil_collect_exec_sections(core, bundle, blake)) {
		return false;
	}

	size_t index = 0;
	rz_pvector_foreach (bo->symbols, it) {
		RzBinSymbol *symbol = (RzBinSymbol *)*it;
		if (!symbol || symbol->is_imported) {
			continue;
		}
		RzAnalysisFunction *func = rz_analysis_get_function_at(analysis, symbol->vaddr);
		if (!func) {
			continue;
		}

		sil_function_v2_t *dst = &bundle->functions[index];
		RzBinSection *section = rz_bin_get_section_at(bo, symbol->paddr, false);
		Signature *signature = sil_function_to_signature(analysis, func, arch, blake, max_size);
		if (!signature) {
			continue;
		}

		dst->addr = func->addr;
		dst->size = rz_analysis_function_linear_size(func);
		dst->name = func->name ? strdup(func->name) : NULL;
		dst->signature = rz_analysis_function_get_signature(func);
		dst->callconv = func->cc ? strdup(func->cc) : NULL;
		if ((func->name && !dst->name) || (func->cc && !dst->callconv) || !sil_copy_signature_to_v2(dst, signature)) {
			proto_signature_free(signature);
			return false;
		}
		if (section) {
			ut64 section_addr = is_va ? section->vaddr : section->paddr;
			dst->section_name = section->name ? strdup(section->name) : NULL;
			if (section->name && !dst->section_name) {
				proto_signature_free(signature);
				return false;
			}
			dst->section_paddr = section->paddr;
			if (func->addr >= section_addr) {
				dst->section_offset = func->addr - section_addr;
			}
		}
		const char *pseudocode_source = "none";
		if (pseudocode_budget >= SIL_PSEUDOCODE_MIN_REMAINING_BYTES) {
			dst->pseudocode = sil_extract_pseudocode(core, sil, func, &dst->loc, &dst->nos, &pseudocode_source);
			dst->pseudocode = sil_trim_pseudocode_budget(dst->pseudocode, &dst->loc, &dst->nos, &pseudocode_budget, &pseudocode_source);
		}
		dst->pseudocode_source = strdup(pseudocode_source);
		if (!dst->pseudocode_source) {
			proto_signature_free(signature);
			return false;
		}
		index++;
		proto_signature_free(signature);
	}

	bundle->n_functions = index;
	return true;
}

static void sil_apply_hint_matches(RzCore *core, const sil_resolve_result_t *matches, sil_stats_t *stats) {
	RzAnalysisFunction *func = NULL;
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	if (!bo) {
		return;
	}

	for (size_t i = 0; i < matches->n_hints; ++i) {
		const sil_hint_v2_t *hint = &matches->hints[i];
		ut64 address = is_va ? rz_bin_object_p2v(bo, hint->offset) : hint->offset;
		RzAnalysisFunction *existing = rz_analysis_get_function_at(core->analysis, address);
		ut32 old_bits = existing ? existing->bits : 0;
		rz_core_analysis_function_add(core, NULL, address, false);
		func = rz_analysis_get_function_at(core->analysis, address);
		if (!func || func->addr != address) {
			rz_core_cmdf(core, "af @ 0x%" PFMT64x, address);
			func = rz_analysis_get_function_at(core->analysis, address);
		}
		if (!func) {
			continue;
		}
		bool changed = existing == NULL;
		if (hint->bits > 0) {
			if (func->bits != hint->bits) {
				changed = true;
			}
			func->bits = hint->bits;
		} else if (existing && old_bits != func->bits) {
			changed = true;
		}
		if (changed) {
			stats->hints++;
		}
	}
}

static void sil_apply_symbol_matches(RzCore *core, const sil_resolve_result_t *matches, sil_stats_t *stats) {
	for (size_t i = 0; i < matches->n_symbols; ++i) {
		const sil_symbol_match_v2_t *match = &matches->symbols[i];
		ut64 address = match->addr;
		RzAnalysisFunction *func = NULL;
		if (!address && match->offset) {
			address = sil_offset_to_addr(core, match->offset);
		}
		if (!address) {
			continue;
		}

		func = rz_analysis_get_function_at(core->analysis, address);
		if ((!func || func->addr != address) && match->offset) {
			address = sil_offset_to_addr(core, match->offset);
			func = rz_analysis_get_function_at(core->analysis, address);
		}
		if (!func || func->addr != address) {
			func = sil_materialize_function(core, address, match->size);
		}
		if (func && func->addr == address && match->symbol) {
			sil_apply_symbol(core, func, match->symbol, stats);
			continue;
		}
		if (match->symbol && RZ_STR_ISNOTEMPTY(match->symbol->name)) {
			rz_name_filter(match->symbol->name, -1, true);
			add_named_flag_at(core, match->symbol->name, address, match->size);
			stats->symbols++;
		}
	}
}

static bool sil_signature_handle(sil_t *sil, Signature *signature, RzCore *core, RzAnalysisFunction *func, sil_stats_t *stats) {
	bool result = true;
	Symbol *message = NULL;
	Status status = STATUS__INTERNAL_ERROR;
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_signature_send(socket, sil->psk, signature),
		sil_protocol_response_recv(socket, &status, (void **)&message),
		{
			result = false;
			goto fail;
		});

	if (status != STATUS__SYMBOL) {
		result = sil_handle_fail_status(status);
	} else if (message) {
		sil_apply_symbol(core, func, message, stats);
	}

fail:
	rz_socket_close(socket);
	rz_socket_free(socket);
	symbol__free_unpacked(message, NULL);
	return result;
}

static bool sil_share_bin_handle(sil_t *sil, ShareBin *sharebin) {
	bool result = true;
	Status status = STATUS__INTERNAL_ERROR;
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_share_bin_send(socket, sil->psk, sharebin),
		sil_protocol_response_recv(socket, &status, NULL),
		{
			result = false;
			goto fail;
		});

	if (status != STATUS__SHARE_WAS_SUCCESSFUL) {
		result = sil_handle_fail_status(status);
	}

fail:
	rz_socket_close(socket);
	rz_socket_free(socket);
	return result;
}

#undef sil_retry_n_times

static SectionHash *sil_section_digest(RzCore *core, RzBinSection *bsect, const RzHashPlugin *blake) {
	ut8 *dgst = NULL, *data = NULL;
	RzHashSize size = 0;
	bool va = rz_config_get_b(core->config, RZ_IO_VA);
	ut64 address = va ? bsect->vaddr : bsect->paddr;

	data = calloc(1, bsect->size);
	if (!data) {
		RZ_LOG_ERROR("silhouette: failed to allocate section buffer\n");
		return NULL;
	}

	rz_io_read_at_mapped(core->io, address, data, bsect->size);

	blake->small_block(data, bsect->size, &dgst, &size);
	free(data);

	SectionHash *message = proto_section_hash_new(bsect->size, bsect->paddr, dgst, size);
	if (!message) {
		RZ_LOG_ERROR("silhouette: failed to allocate SectionHash\n");
		return NULL;
	}
	return message;
}

static bool sil_request_and_apply_hints(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	bool result = true;
	const RzHashPlugin *blake = NULL;
	const RzPVector *sections = NULL;
	RzBinObject *bo = NULL;
	RzBinSection *bsect = NULL;
	Binary *binary = NULL;

	blake = rz_hash_plugin_by_name(core->hash, "blake3");
	if (!blake) {
		RZ_LOG_ERROR("silhouette: failed to get blake3 plugin\n");
		return false;
	}

	bo = rz_bin_cur_object(core->bin);
	if (!bo) {
		RZ_LOG_ERROR("silhouette: failed to get bin object\n");
		return false;
	}

	sections = rz_bin_object_get_sections_all(bo);

	const char *type = bo->plugin ? bo->plugin->name : NULL;
	const char *os = bo->info ? bo->info->os : NULL;

	binary = proto_binary_new(type, os, rz_pvector_len(sections));

	void **it;
	rz_pvector_foreach (sections, it) {
		bsect = (RzBinSection *)*it;
		if (!(bsect->perm & RZ_PERM_X)) {
			continue;
		}

		SectionHash *element = sil_section_digest(core, bsect, blake);
		if (!element) {
			result = false;
			goto bad;
		}
		proto_binary_section_hash_add(binary, element);
	}

	if (binary->n_sections > 0) {
		result = sil_binary_handle(sil, binary, core, stats);
	}

bad:
	proto_binary_free(binary);
	return result;
}

static Signature *sil_function_to_signature(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *arch, const RzHashPlugin *blake, size_t max_pattern) {
	size_t linear_size = 0, current = 0, pattern_size = 0;
	ut8 *pattern = NULL, *mask = NULL, *digest = NULL;
	RzHashSize hash_size = 0;
	Signature *signature = NULL;

	// calculate pattern buffer size
	linear_size = rz_analysis_function_linear_size(fcn);

	pattern_size = RZ_MAX(max_pattern, linear_size);

	// allocate pattern buffer
	if (linear_size < 1 || !(pattern = malloc(pattern_size))) {
		return NULL;
	}

	memset(pattern, 0, pattern_size);

	if (!analysis->iob.read_at(analysis->iob.io, fcn->addr, pattern, (int)linear_size)) {
		goto fail;
	}

	// generate pattern mask
	if (!(mask = rz_analysis_mask(analysis, linear_size, pattern, fcn->addr))) {
		goto fail;
	}

	// apply mask to pattern
	for (size_t i = 0; i < linear_size; ++i) {
		pattern[current + i] &= mask[i];
	}
	free(mask);

	// generate digest for masked pattern
	if (!blake->small_block(pattern, max_pattern, &digest, &hash_size)) {
		goto fail;
	}

	signature = proto_signature_new(arch, fcn->bits, linear_size, digest, hash_size);
	if (!signature) {
		free(digest);
	}

fail:
	free(pattern);
	return signature;
}

static ut32 rz_section_hash(const void *k) {
	RzBinSection *section = (RzBinSection *)k;
	ut32 hash = sdb_hash(section->name);
	ut32 high = section->paddr >> 32;
	ut32 low = section->paddr & UT32_MAX;
	hash ^= low;
	hash ^= high;
	return hash;
}

static int rz_section_cmp(const void *a, const void *b) {
	const RzBinSection *sa = (const RzBinSection *)a;
	const RzBinSection *sb = (const RzBinSection *)b;
	int ret = strcmp(sa->name, sb->name);
	if (ret) {
		return ret;
	}
	return sb->paddr - sa->paddr;
}

static bool sil_has_symbols(RzAnalysis *analysis, RzBinObject *bo) {
	void **it;
	RzBinSymbol *symbol = NULL;
	rz_pvector_foreach (bo->symbols, it) {
		symbol = (RzBinSymbol *)*it;
		if (!symbol->is_imported &&
			rz_analysis_get_function_at(analysis, symbol->vaddr)) {
			return true;
		}
	}
	return false;
}

static bool sil_send_share_bin(sil_t *sil, RzCore *core) {
	if (!sil->can_share) {
		// avoid sharing if is disabled.
		RZ_LOG_INFO("silhouette: sharing is disabled...\n");
		return true;
	}

	const RzHashPlugin *blake = NULL;
	HtPP *ht = NULL;
	HtPPOptions opt = { 0 };
	RzAnalysis *analysis = core->analysis;
	RzBinObject *bo = NULL;
	RzBinSymbol *symbol = NULL;
	void **it = NULL;
	ShareBin message = { 0 };
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);

	if (!(bo = rz_bin_cur_object(core->bin)) ||
		!sil_has_symbols(core->analysis, bo)) {
		// avoid sharing if there is no bin object or no valid symbols.
		RZ_LOG_INFO("silhouette: there are no valid symbols to share.\n");
		return true;
	}

	opt.hashfn = rz_section_hash;
	opt.cmp = rz_section_cmp;
	ht = ht_pp_new_opt(&opt);
	if (!ht) {
		RZ_LOG_ERROR("silhouette: failed to allocate map for sections\n");
		return false;
	}

	const char *bin_type = bo->plugin ? bo->plugin->name : NULL;
	const char *bin_os = bo->info ? bo->info->os : NULL;
	const char *arch = rz_config_get(core->config, RZ_ASM_ARCH);
	size_t max_size = rz_config_get_i(core->config, RZ_SIL_PATTERN_SIZE);

	// in the worse case scenario we will have as many sections as symbols
	size_t max_symbols = rz_pvector_len(bo->symbols);

	if (!proto_share_bin_init(&message, bin_type, bin_os, max_symbols, max_symbols)) {
		return false;
	}

	bool result = true;
	blake = rz_hash_plugin_by_name(core->hash, "blake3");
	if (!blake) {
		RZ_LOG_ERROR("silhouette: failed to get blake3 plugin\n");
		result = false;
		goto fail;
	}

	rz_pvector_foreach (bo->symbols, it) {
		symbol = (RzBinSymbol *)*it;
		if (symbol->is_imported) {
			continue;
		}

		RzAnalysisFunction *func = rz_analysis_get_function_at(analysis, symbol->vaddr);
		if (!func) {
			continue;
		}

		RzBinSection *section = rz_bin_get_section_at(bo, symbol->paddr, false);
		if (!section) {
			RZ_LOG_WARN("silhouette: failed to find section at %08" PFMT64x "\n", func->addr);
			continue;
		}

		if (sil->can_share_sections) {
			ShareSection *sharesec = ht_pp_find(ht, section, NULL);
			if (!sharesec) {
				SectionHash *hash = sil_section_digest(core, section, blake);
				if (!hash) {
					result = false;
					goto fail;
				}

				sharesec = proto_share_section_new(section->name, hash, max_symbols);
				if (!sharesec) {
					RZ_LOG_ERROR("silhouette: failed to allocate share section packet\n");
					proto_section_hash_free(hash);
					result = false;
					goto fail;
				}
				ht_pp_insert(ht, section, sharesec);
				proto_share_bin_share_section_add(&message, sharesec);
			}
			// The offset must be the relative function address from the base address of the section
			ut64 offset = func->addr - (is_va ? section->vaddr : section->paddr);
			proto_share_section_hint_add(sharesec, offset, func->bits);
		}

		if (!sil->can_share_symbols) {
			continue;
		}

		char *funsig = rz_analysis_function_get_signature(func);
		Symbol *psymbol = proto_symbol_new(func->name, funsig, func->cc, func->bits);
		free(funsig);
		if (!psymbol) {
			RZ_LOG_ERROR("silhouette: failed to allocate symbol packet\n");
			result = false;
			goto fail;
		}

		// generate function digest
		Signature *psig = NULL;
		if (!(psig = sil_function_to_signature(analysis, func, arch, blake, max_size))) {
			RZ_LOG_ERROR("silhouette: failed to calculate digest of '%s'\n", func->name);
			result = false;
			goto fail;
		}

		ShareSymbol *sharesym = proto_share_symbol_new(psymbol, psig);
		if (!sharesym) {
			RZ_LOG_ERROR("silhouette: failed to allocate share symbol packet\n");
			proto_symbol_free(psymbol);
			proto_signature_free(psig);
			result = false;
			goto fail;
		}
		proto_share_bin_share_symbol_add(&message, sharesym);
		share_symbol__get_packed_size(sharesym);
	}

	result = sil_share_bin_handle(sil, &message);

	proto_share_bin_fini(&message);

fail:
	ht_pp_free(ht);
	return result;
}

static void *sil_calculate_signature_thread(sil_thread_t *context) {
	RzListIter *it = NULL;
	RzAnalysisFunction *func = NULL;
	Signature *message = NULL;
	sil_signature_t *sig = NULL;
	char *fcn_prefix = NULL;
	RzAnalysis *analysis = context->analysis;
	RzThreadQueue *sigs = context->sigs;
	const RzHashPlugin *blake = context->blake;
	const char *arch = context->arch_name;
	size_t max_size = context->max_size;

	fcn_prefix = rz_str_newf("%s.", context->fcn_prefix);
	size_t fcn_prefix_len = strlen(context->fcn_prefix) + 1;

	rz_list_foreach (analysis->fcns, it, func) {
		if (context->stop) {
			break;
		} else if (!RZ_STR_ISEMPTY(func->name) &&
			strncmp(func->name, fcn_prefix, fcn_prefix_len) &&
			strncmp(func->name, "data.", strlen("data."))) {
			continue;
		}

		message = sil_function_to_signature(analysis, func, arch, blake, max_size);
		if (message) {
			sig = sil_signature_new(func, message);
			rz_th_queue_push(sigs, sig, true);
		}
	}

	free(fcn_prefix);
	rz_th_queue_push(sigs, context->end_marker, true);
	context->end_marker = NULL;
	return NULL;
}

static bool sil_share_program_handle_v2(sil_t *sil, RzCore *core) {
	sil_program_bundle_t bundle = { 0 };
	sil_v2_response_t response = { 0 };
	bool result = false;
	RzSocket *socket = NULL;

	if (!sil->can_share) {
		return true;
	}
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	if (!bo || !sil_has_symbols(core->analysis, bo)) {
		return true;
	}
	if (!sil_build_share_program_bundle(sil, core, &bundle)) {
		goto end;
	}
	sil_capnp_debug_dump_program("share", &bundle);

	socket = sil_socket_new(sil);
	if (!socket) {
		goto end;
	}

	(void)sil_protocol_share_program_v2_send(socket, sil->psk, &bundle);
	if (!sil_protocol_response_v2_recv(socket, &response)) {
		goto end;
	}
	sil_capnp_debug_dump_response("share", &response);

	if (response.status != StatusV2_shareResult) {
		if (sil_v2_can_fallback_silently(sil, response.status, &response)) {
			goto end;
		}
		result = sil_handle_fail_status_v2(response.status, &response);
		goto end;
	}

	result = true;

end:
	if (socket) {
		rz_socket_close(socket);
		rz_socket_free(socket);
	}
	sil_capnp_response_fini(&response);
	sil_capnp_program_fini(&bundle);
	return result;
}

static bool sil_resolve_program_handle_v2(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	sil_program_bundle_t bundle = { 0 };
	sil_v2_response_t response = { 0 };
	bool result = false;
	RzSocket *socket = NULL;

	if (!sil_build_resolve_program_bundle(sil, core, &bundle)) {
		goto end;
	}
	sil_capnp_debug_dump_program("resolve", &bundle);

	socket = sil_socket_new(sil);
	if (!socket) {
		goto end;
	}

	(void)sil_protocol_resolve_program_v2_send(socket, sil->psk, &bundle);
	if (!sil_protocol_response_v2_recv(socket, &response)) {
		RZ_LOG_ERROR("silhouette: failed to receive capnp resolve response\n");
		goto end;
	}
	sil_capnp_debug_dump_response("resolve", &response);

	if (response.status != StatusV2_resolveResult) {
		if (sil_v2_can_fallback_silently(sil, response.status, &response)) {
			goto end;
		}
		result = sil_handle_fail_status_v2(response.status, &response);
		goto end;
	}

	sil_apply_hint_matches(core, &response.resolve_result, stats);
	sil_apply_symbol_matches(core, &response.resolve_result, stats);
	result = true;

end:
	if (socket) {
		rz_socket_close(socket);
		rz_socket_free(socket);
	}
	sil_capnp_response_fini(&response);
	sil_capnp_program_fini(&bundle);
	return result;
}

bool sil_test_connection(sil_t *sil, ut64 *elapsed_usec) {
	rz_return_val_if_fail(sil, false);
	return sil_ping_handle(sil, elapsed_usec);
}

static bool sil_share_binary_v1(sil_t *sil, RzCore *core) {
	rz_return_val_if_fail(sil, false);
	bool old = sil->can_share;
	sil->can_share = true;
	bool res = sil_send_share_bin(sil, core);
	sil->can_share = old;
	return res;
}

static bool sil_resolve_functions_v1(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	rz_return_val_if_fail(sil && core && core->analysis && stats, false);
	bool result = false;
	size_t n_functions = 0;
	RzThreadQueue *sigs = NULL;
	RzThread *th = NULL;
	void *data = NULL;
	sil_thread_t th_info = { 0 };
	RzAnalysis *analysis = core->analysis;
	
	memset(stats, 0, sizeof(sil_stats_t));

	n_functions = rz_list_length(analysis->fcns);
	if (n_functions < 1) {
		result = true;
		RZ_LOG_ERROR("silhouette: there is nothing to do here..\n");
		goto end;
	}

	sigs = rz_th_queue_new(n_functions + 1, (RzListFree)sil_signature_free);
	if (!sigs) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory (queue)\n");
		goto end;
	}

	th_info.blake = rz_hash_plugin_by_name(core->hash, "blake3");
	if (!th_info.blake) {
		RZ_LOG_ERROR("silhouette: failed to get blake3 plugin.\n");
		goto end;
	}

	th_info.analysis = analysis;
	th_info.sigs = sigs;
	th_info.stop = false;
	th_info.max_size = rz_config_get_i(core->config, RZ_SIL_PATTERN_SIZE);
	th_info.arch_name = rz_config_get(core->config, RZ_ASM_ARCH);
	th_info.fcn_prefix = rz_config_get(core->config, RZ_ANALYSIS_FCN_PREFIX);
	th_info.end_marker = sil_signature_new(NULL, NULL);
	if (!th_info.end_marker) {
		RZ_LOG_ERROR("silhouette: failed to allocate queue end marker\n");
		goto end;
	}
	if (RZ_STR_ISEMPTY(th_info.fcn_prefix)) {
		th_info.fcn_prefix = "fcn";
	}

	if (!sil_send_share_bin(sil, core) ||
		!sil_request_and_apply_hints(sil, core, stats)) {
		goto end;
	}

	th = rz_th_new((RzThreadFunction)sil_calculate_signature_thread, &th_info);
	if (!th) {
		RZ_LOG_ERROR("silhouette: failed to spawn signature thread\n");
		goto end;
	}

	result = true;
	while (rz_th_queue_pop(sigs, false, &data)) {
		sil_signature_t *signature = (sil_signature_t *)data;
		if (!signature || !signature->message) {
			sil_signature_free(signature);
			break;
		}

		RzAnalysisFunction *function = signature->function;
		Signature *message = signature->message;

		if (!sil_signature_handle(sil, message, core, function, stats)) {
			th_info.stop = true;
			result = false;
			break;
		}

		sil_signature_free(signature);
		if (!result) {
			break;
		}
	}

	rz_th_wait(th);
	rz_th_free(th);

end:
	sil_signature_free(th_info.end_marker);
	rz_th_queue_free(sigs);
	return result;
}

bool sil_share_binary(sil_t *sil, RzCore *core) {
	rz_return_val_if_fail(sil, false);
	bool old = sil->can_share;
	sil->can_share = true;

	if (sil_prefers_capnp(sil) && sil_share_program_handle_v2(sil, core)) {
		sil->can_share = old;
		return true;
	}
	if (sil_prefers_capnp(sil) && sil_can_fallback_to_protobuf(sil)) {
		RZ_LOG_INFO("silhouette: falling back to protobuf share.\n");
	} else if (sil_prefers_capnp(sil)) {
		sil->can_share = old;
		return false;
	}

	bool res = sil_share_binary_v1(sil, core);
	sil->can_share = old;
	return res;
}

bool sil_resolve_functions(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	rz_return_val_if_fail(sil && core && core->analysis && stats, false);
	memset(stats, 0, sizeof(*stats));

	if (sil_prefers_capnp(sil)) {
		bool shared = sil_share_program_handle_v2(sil, core);
		bool resolved = false;
		if (shared) {
			sil_stats_t total = { 0 };
			for (ut32 pass = 0; pass < 3; ++pass) {
				sil_stats_t round = { 0 };
				if (!sil_resolve_program_handle_v2(sil, core, &round)) {
					resolved = false;
					break;
				}
				total.hints += round.hints;
				total.symbols += round.symbols;
				resolved = true;
				if (round.hints == 0) {
					break;
				}
			}
			if (resolved) {
				*stats = total;
			}
		}
		if (resolved) {
			return true;
		}
		if (sil_can_fallback_to_protobuf(sil)) {
			RZ_LOG_INFO("silhouette: falling back to protobuf resolve.\n");
			memset(stats, 0, sizeof(*stats));
		} else {
			return false;
		}
	}

	return sil_resolve_functions_v1(sil, core, stats);
}
