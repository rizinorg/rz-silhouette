// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_client.c
 * Implements the tcp protocol to talk to the server.
 */

#include "sil.h"
#include "sil_protocol.h"

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

static SectionHash *sil_section_digest(RzCore *core, RzBinSection *bsect, const RzHashPlugin *blake);
static Signature *sil_function_to_signature(RzAnalysis *analysis, RzAnalysisFunction *fcn, const char *arch, const RzHashPlugin *blake, size_t max_pattern);

static char *sil_to_lower_dup(const char *original, const char *def_string) {
	const char *string = RZ_STR_ISEMPTY(original) ? def_string : original;
	size_t length = strlen(string);
	char *s = calloc(sizeof(char), length + 1);
	if (!s) {
		return NULL;
	}
	for (size_t i = 0, j = 0; i < length; ++i) {
		if (!IS_ALPHANUM(string[i])) {
			continue;
		}
		s[j++] = tolower((ut8)string[i]);
	}
	if (strlen(s) < 1) {
		free(s);
		return strdup(def_string);
	}
	return s;
}

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
	const char *message = response && response->which == SilResponse_message ? response->text : NULL;
	switch (status) {
	case SilStatus_internalError:
		RZ_LOG_ERROR("silhouette: internal server error%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	case SilStatus_clientBadPreSharedKey:
		RZ_LOG_ERROR("silhouette: server did not accept the current psk%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	case SilStatus_clientNotAuthorized:
		RZ_LOG_ERROR("silhouette: client was not authorized%s%s.\n", message ? ": " : "", message ? message : "");
		return false;
	case SilStatus_versionMismatch:
		RZ_LOG_ERROR("silhouette: the installed plugin is too old%s%s.\n", message ? ": " : "", message ? message : "");
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

static bool sil_program_bundle_alloc(sil_program_bundle_t *bundle, size_t sections, size_t functions) {
	memset(bundle, 0, sizeof(*bundle));
	bundle->sections = sections > 0 ? calloc(sizeof(sil_section_t), sections) : NULL;
	bundle->functions = functions > 0 ? calloc(sizeof(sil_function_t), functions) : NULL;
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

static bool sil_copy_section(sil_section_t *dst, const RzBinSection *section, SectionHash *hash) {
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

static bool sil_copy_signature(sil_function_t *dst, Signature *signature) {
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
		if (!sil_copy_section(&bundle->sections[index], section, hash)) {
			sil_section_hash_free(hash);
			return false;
		}
		index++;
		sil_section_hash_free(hash);
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
	size_t n_functions = 0;
	RzListIter *it = NULL;
	RzAnalysisFunction *func = NULL;
	(void)sil;

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

	if (!sil_collect_exec_sections(core, bundle, blake)) {
		return false;
	}

	size_t index = 0;
	rz_list_foreach (analysis->fcns, it, func) {
		if (!sil_should_query_function_name(func->name, prefix)) {
			continue;
		}

		sil_function_t *dst = &bundle->functions[index];
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
		if ((func->name && !dst->name) || (func->cc && !dst->callconv) || !sil_copy_signature(dst, signature)) {
			sil_signature_free(signature);
			return false;
		}

		if (section) {
			ut64 section_addr = is_va ? section->vaddr : section->paddr;
			dst->section_name = section->name ? strdup(section->name) : NULL;
			if (section->name && !dst->section_name) {
				sil_signature_free(signature);
				return false;
			}
			dst->section_paddr = section->paddr;
			if (func->addr >= section_addr) {
				dst->section_offset = func->addr - section_addr;
			}
		}
		index++;
		sil_signature_free(signature);
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
	size_t n_functions = 0;
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

	bundle->binary_type = bo->plugin ? sil_to_lower_dup(bo->plugin->name, "any") : strdup("any");
	bundle->os = bo->info ? sil_to_lower_dup(bo->info->os, "any") : strdup("any");
	bundle->arch = sil_to_lower_dup(arch, "any");
	if (!bundle->binary_type || !bundle->os || !bundle->arch) {
		return false;
	}
	bundle->bits = rz_config_get_i(core->config, RZ_ASM_BITS);

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

		sil_function_t *dst = &bundle->functions[index];
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
		if ((func->name && !dst->name) || (func->cc && !dst->callconv) || !sil_copy_signature(dst, signature)) {
			sil_signature_free(signature);
			return false;
		}
		if (section) {
			ut64 section_addr = is_va ? section->vaddr : section->paddr;
			dst->section_name = section->name ? strdup(section->name) : NULL;
			if (section->name && !dst->section_name) {
				sil_signature_free(signature);
				return false;
			}
			dst->section_paddr = section->paddr;
			if (func->addr >= section_addr) {
				dst->section_offset = func->addr - section_addr;
			}
		}
		index++;
		sil_signature_free(signature);
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
		const sil_hint_t *hint = &matches->hints[i];
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

	data = calloc(1, bsect->size);
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

	signature = RZ_NEW0(Signature);
	if (!signature) {
		free(digest);
		goto fail;
	}
	signature->arch = sil_to_lower_dup(arch, "any");
	signature->bits = fcn->bits;
	signature->length = linear_size;
	signature->digest.data = digest;
	signature->digest.len = hash_size;
	if (!signature->arch) {
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
