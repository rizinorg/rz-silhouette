// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_client.c
 * Implements the tcp protocol to talk to the server.
 *
 * The protocol is very simple, push the size of the data
 * stream that is sent afterwards as a packed protobuf structure.
 */

#include "sil.h"
#include "sil_helpers.h"
#include "sil_protocol.h"

#define SIL_RETRY_TIMES (3)

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
	const RzHashPlugin *blake;
	void *md;
} sil_hash_ctx_t;

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
	size_t max_size;
	bool stop;
} sil_thread_t;

static void sil_signature_free(sil_signature_t *signature) {
	if (!signature) {
		return;
	}
	proto_signature_free(signature->message);
	free(signature);
}

#define sil_signature_empty_new(function) sil_signature_new(function, NULL)
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
	free(sil);
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

	if (!rz_socket_connect_tcp(socket, sil->address, sil->port, sil->timeout)) {
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

#define sil_retry_n_times(n_times, send, recv, fail) \
	for (int i = 0; i < (n_times + 1); ++i) { \
		if (i > n_times) { \
			fail \
		} \
		if (send && recv) { \
			break; \
		} \
	}

static bool sil_ping_handle(sil_t *sil) {
	bool result = true;
	Message *message = NULL;
	Status status = STATUS__INTERNAL_ERROR;
	RzSocket *socket = sil_socket_new(sil);
	if (!socket) {
		return false;
	}

	sil_retry_n_times(SIL_RETRY_TIMES,
		sil_protocol_ping_send(socket, sil->psk),
		sil_protocol_response_recv(socket, &status, (void **)&message),
		{
			result = false;
			goto fail;
		});

	if (status != STATUS__MESSAGE) {
		sil_handle_fail_status(status);
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
		sil_handle_fail_status(status);
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
		return ht_pp_find(analysis->ht_name_fun, name, NULL) == NULL;
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

	RzBinFile *bf = rz_bin_cur(core->bin);
	if (!bf || !bf->o || !bf->o->symbols) {
		return;
	}

	size_t offset = !strncmp(name, "sym.", strlen("sym.")) ? strlen("sym.") : 0;

	ut64 paddr = is_va ? rz_bin_object_v2p(bf->o, fcn->addr) : fcn->addr;
	RzBinSymbol *symbol = rz_bin_symbol_new(name + offset, paddr, fcn->addr);
	if (!symbol) {
		RZ_LOG_ERROR("Failed allocate new go symbol\n");
		return;
	}

	symbol->size = size;
	symbol->bind = RZ_BIN_BIND_GLOBAL_STR;
	symbol->type = RZ_BIN_TYPE_FUNC_STR;
	if (!rz_list_append(bf->o->symbols, symbol)) {
		RZ_LOG_ERROR("Failed append new go symbol to symbols list\n");
		rz_bin_symbol_free(symbol);
	}
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
		sil_handle_fail_status(status);
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
		sil_handle_fail_status(status);
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

	rz_io_read_at(core->io, address, data, bsect->size);

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
	const RzList *list = NULL;
	RzBinObject *bo = NULL;
	RzBinSection *bsect = NULL;
	RzListIter *it = NULL;
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

	list = rz_bin_object_get_sections_all(bo);

	const char *type = bo->plugin ? bo->plugin->name : NULL;
	const char *os = bo->info ? bo->info->os : NULL;

	binary = proto_binary_new(type, os, rz_list_length(list));

	rz_list_foreach (list, it, bsect) {
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
	RzListIter *it;
	RzBinSymbol *symbol = NULL;
	rz_list_foreach (bo->symbols, it, symbol) {
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
	RzListIter *it = NULL;
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
	size_t max_symbols = rz_list_length(bo->symbols);

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

	rz_list_foreach (bo->symbols, it, symbol) {
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

	// always push an empty signature to inform main thread to stop.
	sig = sil_signature_empty_new(func);
	rz_th_queue_push(sigs, sig, true);
	free(fcn_prefix);
	return NULL;
}

bool sil_test_connection(sil_t *sil) {
	rz_return_val_if_fail(sil, false);

	bool old = sil->show_msg;
	sil->show_msg = true;
	bool res = sil_ping_handle(sil);
	sil->show_msg = old;
	return res;
}

bool sil_share_binary(sil_t *sil, RzCore *core) {
	rz_return_val_if_fail(sil, false);
	bool old = sil->can_share;
	sil->can_share = true;
	bool res = sil_send_share_bin(sil, core);
	sil->can_share = old;
	return res;
}

bool sil_resolve_functions(sil_t *sil, RzCore *core, sil_stats_t *stats) {
	rz_return_val_if_fail(sil && core && core->analysis && stats, false);
	bool result = false;
	size_t n_functions = 0;
	RzThreadQueue *sigs = NULL;
	RzThread *th = NULL;
	sil_thread_t th_info = { 0 };
	RzAnalysis *analysis = core->analysis;
	sil_signature_t *signature = NULL;

	memset(stats, 0, sizeof(sil_stats_t));

	n_functions = rz_list_length(analysis->fcns);
	if (n_functions < 1) {
		result = true;
		RZ_LOG_ERROR("silhouette: there is nothing to do here..\n");
		goto end;
	}

	sigs = rz_th_queue_new(n_functions, (RzListFree)sil_signature_free);
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
	while ((signature = rz_th_queue_wait_pop(sigs, false))) {
		if (!signature->message) {
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
	rz_th_queue_free(sigs);
	return result;
}
