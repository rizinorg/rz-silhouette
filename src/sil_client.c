// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_client.c
 * Implements the tcp protocol to talk to the server.
 */

#include "sil.h"
#include "sil_helpers.h"
#include "sil_protocol.h"
#include <rz_th.h>

#define SIL_RETRY_TIMES (3)
#define SIL_MATERIALIZE_MAX_BB_SIZE 256U
#define SIL_MATERIALIZE_FALLBACK_BB_SIZE 16U
#define SIL_MATERIALIZE_MAX_OPS 32U

typedef struct sil_s {
	char *psk;
	char *address;
	char *port;
	ut32 timeout;
	bool use_tls;
	bool show_msg;
	bool can_share;
	bool can_share_sections;
	bool can_share_symbols;
} sil_t;

typedef struct {
	RzAnalysisFunction *func;
	ut64 addr;
	char *name;
	char *signature;
	char *callconv;
	char *section_name;
	ut64 section_paddr;
	ut64 section_addr;
} sil_function_job_t;

typedef struct {
	RzAnalysis *analysis;
	const RzHashPlugin *blake;
	const char *arch;
	size_t max_pattern;
} sil_bundle_build_cfg_t;

typedef struct {
	const sil_function_job_t *jobs;
	size_t n_jobs;
	sil_function_t *outputs;
	bool *ready;
	const sil_bundle_build_cfg_t *cfg;
	bool success;
} sil_bundle_async_ctx_t;

typedef enum {
	SIL_BUNDLE_ENTRY_SKIP = 0,
	SIL_BUNDLE_ENTRY_READY,
	SIL_BUNDLE_ENTRY_ERROR,
} sil_bundle_entry_status_t;

static SectionHash *sil_section_digest(RzCore *core, RzBinSection *bsect, const RzHashPlugin *blake);
static Signature *sil_function_to_signature(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *arch, const RzHashPlugin *blake, size_t max_pattern);
static bool sil_collect_exec_sections(RzCore *core, sil_program_bundle_t *bundle, const RzHashPlugin *blake);

void sil_free(sil_t *sil) {
	if (!sil) {
		return;
	}
	free(sil->psk);
	free(sil->address);
	free(sil->port);
	free(sil);
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
	size_t offset = rz_str_startswith(name, "sym.") ? 4 : 0;
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

static ut32 sil_timeout_to_socket_seconds(ut32 timeout_ms) {
	if (!timeout_ms) {
		return 0;
	}
	return (timeout_ms + 999) / 1000;
}

static char *sil_dup_arch_or_fail(const char *arch) {
	char *normalized = sil_to_lower_dup(arch, NULL);
	if (!normalized) {
		RZ_LOG_ERROR("silhouette: missing or invalid analysis arch\n");
	}
	return normalized;
}

sil_t *sil_new(sil_opt_t *opts) {
	rz_return_val_if_fail(opts, NULL);

	sil_t *sil = RZ_NEW0(sil_t);
	if (!sil) {
		return NULL;
	}

	sil->psk = rz_str_dup(opts->psk);
	sil->address = rz_str_dup(opts->address);
	sil->port = rz_str_dup(opts->port);
	sil->timeout = opts->timeout;
	sil->use_tls = opts->use_tls;
	sil->show_msg = opts->show_msg;
	sil->can_share = opts->can_share;
	sil->can_share_sections = opts->can_share_sections;
	sil->can_share_symbols = opts->can_share_symbols;

	if (RZ_STR_ISEMPTY(sil->address)) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory or empty string (address)\n");
		goto fail;
	} else if (RZ_STR_ISEMPTY(sil->port)) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory or empty string (port)\n");
		goto fail;
	} else if (RZ_STR_ISEMPTY(sil->psk)) {
		RZ_LOG_ERROR("silhouette: failed to allocate memory or empty string (psk)\n");
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

static bool sil_handle_fail_status(enum SilStatus status, const sil_response_t *response) {
	bool has_message = response && response->which == SilResponse_message && RZ_STR_ISNOTEMPTY(response->text);
	const char *message = rz_str_get(has_message ? response->text : NULL);
	switch (status) {
	case SilStatus_internalError:
		RZ_LOG_ERROR("silhouette: internal server error%s%s.\n", has_message ? ": " : "", message);
		return false;
	case SilStatus_clientBadPreSharedKey:
		RZ_LOG_ERROR("silhouette: server did not accept the current psk%s%s.\n", has_message ? ": " : "", message);
		return false;
	case SilStatus_clientNotAuthorized:
		RZ_LOG_ERROR("silhouette: client was not authorized%s%s.\n", has_message ? ": " : "", message);
		return false;
	case SilStatus_versionMismatch:
		RZ_LOG_ERROR("silhouette: the installed plugin is too old%s%s.\n", has_message ? ": " : "", message);
		return false;
	default:
		RZ_LOG_ERROR("silhouette: could not understand the capnp response from the server %u.\n", status);
		return false;
	}
}

static void sil_show_server_info(const sil_t *sil, const sil_server_info_t *info) {
	if (!sil || !sil->show_msg || !info) {
		return;
	}
	rz_cons_printf("silhouette server: protocol %u, tls=%s\n",
		info->version,
		info->tls_required ? "required" : "optional");
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

static bool sil_ping_handle(sil_t *sil, ut64 *elapsed_usec) {
	bool result = true;
	sil_response_t response = { 0 };
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	ut64 started_usec = rz_time_now();
	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_ping_send(socket, sil->psk),
		sil_protocol_response_recv(socket, &response),
		{
			sil_measure_latency_add(elapsed_usec, started_usec);
			result = false;
			goto fail;
		});
	sil_measure_latency_add(elapsed_usec, started_usec);
	sil_capnp_debug_dump_response("ping", &response);

	if (response.status != SilStatus_serverInfo) {
		result = sil_handle_fail_status(response.status, &response);
	} else {
		sil_show_server_info(sil, &response.server_info);
	}

fail:
	rz_socket_close(socket);
	rz_socket_free(socket);
	sil_capnp_response_fini(&response);
	return result;
}

static bool sil_ping(sil_t *sil, ut64 *elapsed_usec) {
	if (elapsed_usec) {
		*elapsed_usec = 0;
	}
	return sil_ping_handle(sil, elapsed_usec);
}

static bool try_rename_function(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *name) {
	if (fcn->type == RZ_ANALYSIS_FCN_TYPE_SYM) {
		// do not rename if is a symbol but check if
		// another function has the same name
		return !rz_analysis_function_exists_with_name(analysis, name);
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
	const bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	const char *prefix = rz_config_get(core->config, RZ_ANALYSIS_FCN_PREFIX);
	if (RZ_STR_ISEMPTY(prefix)) {
		prefix = "fcn";
	}

	// remove old flag
	char *old_prefix = rz_str_newf("%s.", prefix);
	RzFlagItem *fit = rz_flag_get_by_spaces(core->flags, fcn->addr, old_prefix, "data.", NULL);
	free(old_prefix);

	ut64 size = fit->size;
	if (fit) {
		rz_flag_unset(core->flags, fit);
	}

	// set new flag
	rz_flag_set(core->flags, name, fcn->addr, size);

	(void)is_va;
	sil_upsert_bin_symbol(core, name, fcn->addr, size);
}

static void add_named_flag_at(RzCore *core, const char *name, ut64 addr, ut64 size) {
	if (!core || RZ_STR_ISEMPTY(name)) {
		return;
	}

	rz_flag_set(core->flags, name, addr, size);

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
	RzAnalysis *analysis = core->analysis;
	RzAnalysisFunction *func = rz_analysis_get_function_at(analysis, address);
	if (func && func->addr == address) {
		return func;
	}

	if (!func) {
		rz_core_analysis_function_add(core, NULL, address, false);
		func = rz_analysis_get_function_at(analysis, address);
		if (func && func->addr == address) {
			return func;
		}
	}

	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	ut32 bb_size = sil_estimate_materialized_bb_size(core, address, size, &jump, &fail);
	bool created = false;

	if (!func || func->addr != address) {
		func = rz_analysis_create_function(analysis, NULL, address, RZ_ANALYSIS_FCN_TYPE_FCN);
		if (func) {
			created = true;
		} else {
			func = rz_analysis_get_function_at(analysis, address);
			if (!func || func->addr != address) {
				return NULL;
			}
		}
	}

	if (!rz_analysis_fcn_add_bb(analysis, func, address, bb_size, jump, fail)) {
		if (created) {
			rz_analysis_function_delete(func);
		}
		return NULL;
	}

	func = rz_analysis_get_function_at(analysis, address);
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
		fcn->cc = rz_str_constpool_get(rz_analysis_get_const_pool(core->analysis), symbol->callconv);
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
	return !rz_str_startswith(name, "sym.imp.");
}

static bool sil_program_bundle_alloc(sil_program_bundle_t *bundle, size_t sections, size_t functions) {
	memset(bundle, 0, sizeof(*bundle));
	bundle->sections = sections > 0 ? RZ_NEWS0(sil_section_t, sections) : NULL;
	bundle->functions = functions > 0 ? RZ_NEWS0(sil_function_t, functions) : NULL;
	return (sections == 0 || bundle->sections) && (functions == 0 || bundle->functions);
}

static bool sil_copy_section(sil_section_t *dst, const RzBinSection *section, SectionHash *hash) {
	if (!dst) {
		return false;
	}
	dst->name = section && section->name ? rz_str_dup(section->name) : NULL;
	if (section && section->name && !dst->name) {
		return false;
	}
	dst->size = hash ? hash->size : 0;
	dst->paddr = hash ? hash->paddr : 0;
	dst->digest_size = hash ? hash->digest.len : 0;
	if (dst->digest_size > 0) {
		dst->digest = rz_mem_dup(hash->digest.data, (int)dst->digest_size);
		if (!dst->digest) {
			return false;
		}
	}
	return true;
}

static bool sil_copy_signature(sil_function_t *dst, Signature *signature) {
	if (!dst || !signature) {
		return false;
	}
	dst->bits = signature->bits;
	dst->length = signature->length;
	dst->arch = signature->arch ? rz_str_dup(signature->arch) : NULL;
	if (signature->arch && !dst->arch) {
		return false;
	}
	dst->digest_size = signature->digest.len;
	if (dst->digest_size > 0) {
		dst->digest = rz_mem_dup(signature->digest.data, (int)dst->digest_size);
		if (!dst->digest) {
			return false;
		}
	}
	return true;
}

static void sil_function_job_fini(sil_function_job_t *job) {
	if (!job) {
		return;
	}
	free(job->name);
	free(job->signature);
	free(job->callconv);
	free(job->section_name);
	memset(job, 0, sizeof(*job));
}

static void sil_function_entry_fini(sil_function_t *function) {
	if (!function) {
		return;
	}
	free(function->arch);
	free(function->digest);
	free(function->section_name);
	free(function->name);
	free(function->signature);
	free(function->callconv);
	memset(function, 0, sizeof(*function));
}

static bool sil_prepare_function_job(sil_function_job_t *job, RzAnalysisFunction *func, RzBinSection *section, ut64 section_addr) {
	if (!job || !func) {
		return false;
	}
	job->func = func;
	job->addr = func->addr;
	job->name = func->name ? rz_str_dup(func->name) : NULL;
	job->signature = rz_analysis_function_get_signature(func);
	job->callconv = func->cc ? rz_str_dup(func->cc) : NULL;
	job->section_name = section && section->name ? rz_str_dup(section->name) : NULL;
	job->section_paddr = section ? section->paddr : 0;
	job->section_addr = section_addr;
	if ((func->name && !job->name) || (func->cc && !job->callconv) || (section && section->name && !job->section_name)) {
		sil_function_job_fini(job);
		return false;
	}
	return true;
}

static sil_bundle_entry_status_t sil_build_function_entry(sil_function_t *dst, const sil_function_job_t *job, const sil_bundle_build_cfg_t *cfg) {
	if (!dst || !job || !job->func || !cfg) {
		return SIL_BUNDLE_ENTRY_ERROR;
	}

	Signature *signature = sil_function_to_signature(cfg->analysis, job->func, cfg->arch, cfg->blake, cfg->max_pattern);
	if (!signature) {
		return SIL_BUNDLE_ENTRY_SKIP;
	}

	sil_function_t local = { 0 };
	local.addr = job->addr;
	local.size = signature->length;
	local.name = job->name ? rz_str_dup(job->name) : NULL;
	local.signature = job->signature ? rz_str_dup(job->signature) : NULL;
	local.callconv = job->callconv ? rz_str_dup(job->callconv) : NULL;
	if ((job->name && !local.name) || (job->signature && !local.signature) || (job->callconv && !local.callconv) || !sil_copy_signature(&local, signature)) {
		sil_signature_free(signature);
		sil_function_entry_fini(&local);
		return SIL_BUNDLE_ENTRY_ERROR;
	}

	if (job->section_name) {
		local.section_name = rz_str_dup(job->section_name);
		if (!local.section_name) {
			sil_signature_free(signature);
			sil_function_entry_fini(&local);
			return SIL_BUNDLE_ENTRY_ERROR;
		}
		local.section_paddr = job->section_paddr;
		if (local.addr >= job->section_addr) {
			local.section_offset = local.addr - job->section_addr;
		}
	}

	sil_signature_free(signature);
	*dst = local;
	return SIL_BUNDLE_ENTRY_READY;
}

static bool sil_build_function_entries_serial(const sil_function_job_t *jobs, size_t n_jobs, const sil_bundle_build_cfg_t *cfg, sil_function_t *outputs, bool *ready) {
	for (size_t i = 0; i < n_jobs; ++i) {
		switch (sil_build_function_entry(&outputs[i], &jobs[i], cfg)) {
		case SIL_BUNDLE_ENTRY_READY:
			ready[i] = true;
			break;
		case SIL_BUNDLE_ENTRY_SKIP:
			break;
		case SIL_BUNDLE_ENTRY_ERROR:
			return false;
		}
	}
	return true;
}

static void *sil_build_function_entries_thread(sil_bundle_async_ctx_t *ctx) {
	ctx->success = sil_build_function_entries_serial(ctx->jobs, ctx->n_jobs, ctx->cfg, ctx->outputs, ctx->ready);
	return NULL;
}

static size_t sil_compact_function_entries(sil_function_t *functions, bool *ready, size_t n_functions) {
	size_t out = 0;
	for (size_t i = 0; i < n_functions; ++i) {
		if (!ready[i]) {
			continue;
		}
		if (out != i) {
			functions[out] = functions[i];
			memset(&functions[i], 0, sizeof(functions[i]));
		}
		out++;
	}
	return out;
}

static bool sil_collect_sections_and_populate_functions(RzCore *core, sil_program_bundle_t *bundle, const sil_function_job_t *jobs, size_t n_jobs, const sil_bundle_build_cfg_t *cfg, const RzHashPlugin *blake) {
	if (n_jobs == 0) {
		bundle->n_functions = 0;
		return sil_collect_exec_sections(core, bundle, blake);
	}

	bool *ready = RZ_NEWS0(bool, n_jobs);
	if (!ready) {
		return false;
	}

	bundle->n_functions = n_jobs;
	bool success = false;
	RzThread *thread = NULL;
	sil_bundle_async_ctx_t ctx = {
		.jobs = jobs,
		.n_jobs = n_jobs,
		.outputs = bundle->functions,
		.ready = ready,
		.cfg = cfg,
		.success = false,
	};
	if (n_jobs > 1) {
		thread = rz_th_new((RzThreadFunction)sil_build_function_entries_thread, &ctx);
		if (!thread) {
			RZ_LOG_WARN("silhouette: failed to start bundle worker, falling back to single-threaded build\n");
		}
	}
	RZ_LOG_DEBUG("silhouette: building %zu function entries using %s\n", n_jobs, thread ? "1 background worker thread" : "the main thread");

	bool sections_ok = sil_collect_exec_sections(core, bundle, blake);
	if (thread) {
		rz_th_wait(thread);
		success = ctx.success;
		rz_th_free(thread);
	} else {
		success = sil_build_function_entries_serial(jobs, n_jobs, cfg, bundle->functions, ready);
	}

	success = success && sections_ok;
	if (success) {
		bundle->n_functions = sil_compact_function_entries(bundle->functions, ready, n_jobs);
	}
	free(ready);
	return success;
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
		if (!sil_copy_section(&bundle->sections[index], section, hash)) {
			sil_section_hash_free(hash);
			return false;
		}
		bundle->n_sections = index + 1;
		index++;
		sil_section_hash_free(hash);
	}
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
	size_t n_functions = 0;
	sil_function_job_t *jobs = NULL;
	RzListIter *it = NULL;
	RzAnalysisFunction *func = NULL;
	(void)sil;

	if (!bo || !analysis || !blake) {
		return false;
	}
	if (RZ_STR_ISEMPTY(prefix)) {
		prefix = "fcn";
	}

	RzList *fcns = rz_analysis_function_list(analysis);
	rz_list_foreach (fcns, it, func) {
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
	jobs = n_functions > 0 ? RZ_NEWS0(sil_function_job_t, n_functions) : NULL;
	if (n_functions > 0 && !jobs) {
		return false;
	}

	bundle->binary_type = bo->plugin ? sil_to_lower_dup(bo->plugin->name, "any") : rz_str_dup("any");
	bundle->os = bo->info ? sil_to_lower_dup(bo->info->os, "any") : rz_str_dup("any");
	bundle->arch = sil_dup_arch_or_fail(arch);
	if (!bundle->binary_type || !bundle->os || !bundle->arch) {
		free(jobs);
		return false;
	}
	bundle->bits = rz_config_get_i(core->config, RZ_ASM_BITS);

	size_t index = 0;
	rz_list_foreach (fcns, it, func) {
		if (!sil_should_query_function_name(func->name, prefix)) {
			continue;
		}

		RzBinSection *section = rz_bin_get_section_at(bo, func->addr, rz_config_get_b(core->config, RZ_IO_VA));
		if (!sil_prepare_function_job(&jobs[index], func, section, section ? (is_va ? section->vaddr : section->paddr) : 0)) {
			for (size_t j = 0; j <= index; ++j) {
				sil_function_job_fini(&jobs[j]);
			}
			free(jobs);
			return false;
		}
		index++;
	}
	sil_bundle_build_cfg_t cfg = {
		.analysis = analysis,
		.blake = blake,
		.arch = bundle->arch,
		.max_pattern = max_size,
	};
	bool ok = sil_collect_sections_and_populate_functions(core, bundle, jobs, index, &cfg, blake);
	for (size_t i = 0; i < index; ++i) {
		sil_function_job_fini(&jobs[i]);
	}
	free(jobs);
	return ok;
}

static bool sil_build_share_program_bundle(sil_t *sil, RzCore *core, sil_program_bundle_t *bundle) {
	const RzHashPlugin *blake = rz_hash_plugin_by_name(core->hash, "blake3");
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	RzAnalysis *analysis = core->analysis;
	const char *arch = rz_config_get(core->config, RZ_ASM_ARCH);
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	size_t max_size = rz_config_get_i(core->config, RZ_SIL_PATTERN_SIZE);
	size_t n_functions = 0;
	sil_function_job_t *jobs = NULL;
	void **it = NULL;
	(void)sil;

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
	jobs = n_functions > 0 ? RZ_NEWS0(sil_function_job_t, n_functions) : NULL;
	if (n_functions > 0 && !jobs) {
		return false;
	}

	bundle->binary_type = bo->plugin ? sil_to_lower_dup(bo->plugin->name, "any") : rz_str_dup("any");
	bundle->os = bo->info ? sil_to_lower_dup(bo->info->os, "any") : rz_str_dup("any");
	bundle->arch = sil_dup_arch_or_fail(arch);
	if (!bundle->binary_type || !bundle->os || !bundle->arch) {
		free(jobs);
		return false;
	}
	bundle->bits = rz_config_get_i(core->config, RZ_ASM_BITS);

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

		RzBinSection *section = rz_bin_get_section_at(bo, symbol->paddr, false);
		if (!sil_prepare_function_job(&jobs[index], func, section, section ? (is_va ? section->vaddr : section->paddr) : 0)) {
			for (size_t j = 0; j <= index; ++j) {
				sil_function_job_fini(&jobs[j]);
			}
			free(jobs);
			return false;
		}
		index++;
	}
	sil_bundle_build_cfg_t cfg = {
		.analysis = analysis,
		.blake = blake,
		.arch = bundle->arch,
		.max_pattern = max_size,
	};
	bool ok = sil_collect_sections_and_populate_functions(core, bundle, jobs, index, &cfg, blake);
	for (size_t i = 0; i < index; ++i) {
		sil_function_job_fini(&jobs[i]);
	}
	free(jobs);
	return ok;
}

static void sil_apply_hint_matches(RzCore *core, const sil_resolve_result_t *matches, sil_stats_t *stats) {
	RzAnalysisFunction *func = NULL;
	bool is_va = rz_config_get_b(core->config, RZ_IO_VA);
	RzBinObject *bo = rz_bin_cur_object(core->bin);
	if (!bo) {
		return;
	}

	for (size_t i = 0; i < matches->n_hints; ++i) {
		const sil_hint_t *hint = &matches->hints[i];
		ut64 address = is_va ? rz_bin_object_p2v(bo, hint->offset) : hint->offset;
		RzAnalysisFunction *existing = rz_analysis_get_function_at(core->analysis, address);
		ut32 old_bits = existing ? existing->bits : 0;
		rz_core_analysis_function_add(core, NULL, address, false);
		func = rz_analysis_get_function_at(core->analysis, address);
		if (!func || func->addr != address) {
			rz_core_analysis_function_add(core, NULL, address, true);
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
		const sil_symbol_match_t *match = &matches->symbols[i];
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

#undef sil_retry_n_times

static SectionHash *sil_section_digest(RzCore *core, RzBinSection *bsect, const RzHashPlugin *blake) {
	ut8 *dgst = NULL, *data = NULL;
	RzHashSize size = 0;
	bool va = rz_config_get_b(core->config, RZ_IO_VA);
	ut64 address = va ? bsect->vaddr : bsect->paddr;

	data = RZ_NEWS0(ut8, bsect->size);
	if (!data) {
		RZ_LOG_ERROR("silhouette: failed to allocate section buffer\n");
		return NULL;
	}

	rz_io_read_at_mapped(core->io, address, data, bsect->size);

	blake->small_block(data, bsect->size, &dgst, &size);
	free(data);

	SectionHash *message = RZ_NEW0(SectionHash);
	if (!message) {
		free(dgst);
		RZ_LOG_ERROR("silhouette: failed to allocate SectionHash\n");
		return NULL;
	}
	message->size = bsect->size;
	message->paddr = bsect->paddr;
	message->digest.data = dgst;
	message->digest.len = size;
	return message;
}

static Signature *sil_function_to_signature(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *arch, const RzHashPlugin *blake, size_t max_pattern) {
	size_t linear_size = 0, pattern_size = 0;
	ut8 *pattern = NULL, *mask = NULL, *digest = NULL;
	RzHashSize hash_size = 0;
	Signature *signature = NULL;

	// calculate pattern buffer size
	linear_size = rz_analysis_function_linear_size(fcn);

	pattern_size = RZ_MAX(max_pattern, linear_size);

	// allocate pattern buffer
	if (linear_size < 1 || !(pattern = RZ_NEWS0(ut8, pattern_size))) {
		return NULL;
	}

	RzIOBind *iob = rz_analysis_get_io_bind(analysis);
	if (!iob->read_at(iob->io, fcn->addr, pattern, (int)linear_size)) {
		goto fail;
	}

	// generate pattern mask
	if (!(mask = rz_analysis_mask(analysis, linear_size, pattern, fcn->addr))) {
		goto fail;
	}

	// apply mask to pattern
	for (size_t i = 0; i < linear_size; ++i) {
		pattern[i] &= mask[i];
	}
	free(mask);

	// generate digest for masked pattern
	if (!blake->small_block(pattern, max_pattern, &digest, &hash_size)) {
		goto fail;
	}

	signature = RZ_NEW0(Signature);
	if (!signature) {
		free(digest);
		goto fail;
	}
	signature->arch = rz_str_dup(arch);
	signature->bits = fcn->bits;
	signature->length = linear_size;
	signature->digest.data = digest;
	signature->digest.len = hash_size;
	if (RZ_STR_ISEMPTY(arch) || !signature->arch) {
		RZ_LOG_ERROR("silhouette: missing or invalid analysis arch\n");
		sil_signature_free(signature);
		signature = NULL;
	}

fail:
	free(pattern);
	return signature;
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

static bool sil_share_program_handle(sil_t *sil, RzCore *core) {
	sil_program_bundle_t bundle = { 0 };
	sil_response_t response = { 0 };
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

	(void)sil_protocol_share_program_send(socket, sil->psk, &bundle);
	if (!sil_protocol_response_recv(socket, &response)) {
		goto end;
	}
	sil_capnp_debug_dump_response("share", &response);

	if (response.status != SilStatus_shareResult) {
		result = sil_handle_fail_status(response.status, &response);
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

static bool sil_resolve_program_handle(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	sil_program_bundle_t bundle = { 0 };
	sil_response_t response = { 0 };
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

	(void)sil_protocol_resolve_program_send(socket, sil->psk, &bundle);
	if (!sil_protocol_response_recv(socket, &response)) {
		RZ_LOG_ERROR("silhouette: failed to receive capnp resolve response\n");
		goto end;
	}
	sil_capnp_debug_dump_response("resolve", &response);

	if (response.status != SilStatus_resolveResult) {
		result = sil_handle_fail_status(response.status, &response);
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
	return sil_ping(sil, elapsed_usec);
}

bool sil_share_binary(sil_t *sil, RzCore *core) {
	rz_return_val_if_fail(sil, false);
	bool old = sil->can_share;
	sil->can_share = true;
	bool res = sil_share_program_handle(sil, core);
	sil->can_share = old;
	return res;
}

bool sil_resolve_functions(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	rz_return_val_if_fail(sil && core && core->analysis && stats, false);
	memset(stats, 0, sizeof(*stats));
	bool shared = sil_share_program_handle(sil, core);
	bool resolved = false;
	if (!shared) {
		return false;
	}

	sil_stats_t total = { 0 };
	for (ut32 pass = 0; pass < 3; ++pass) {
		sil_stats_t round = { 0 };
		if (!sil_resolve_program_handle(sil, core, &round)) {
			return false;
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
	return resolved;
}
