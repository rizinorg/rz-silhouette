// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sil_capnp.h"
#include "sil_helpers.h"

static const char *sil_capnp_safe_text(const char *text, const char *fallback) {
	return RZ_STR_ISNOTEMPTY(text) ? text : fallback;
}

void sil_capnp_program_fini(sil_program_bundle_t *program) {
	if (!program) {
		return;
	}
	free(program->binary_type);
	free(program->os);
	free(program->arch);
	free(program->binary_id);
	for (size_t i = 0; i < program->n_sections; ++i) {
		free(program->sections[i].name);
		free(program->sections[i].digest);
	}
	free(program->sections);
	for (size_t i = 0; i < program->n_functions; ++i) {
		sil_function_v2_t *function = &program->functions[i];
		free(function->arch);
		free(function->digest);
		free(function->section_name);
		free(function->pseudocode);
		free(function->pseudocode_source);
		free(function->calls);
		free(function->name);
		free(function->signature);
		free(function->callconv);
	}
	free(program->functions);
	memset(program, 0, sizeof(*program));
}

static void sil_capnp_server_info_fini(sil_server_info_t *info) {
	free(info->model_version);
	free(info->index_version);
	memset(info, 0, sizeof(*info));
}

static void sil_capnp_resolve_result_fini(sil_resolve_result_t *result) {
	for (size_t i = 0; i < result->n_hints; ++i) {
		free(result->hints[i].matched_binary_id);
	}
	free(result->hints);
	for (size_t i = 0; i < result->n_symbols; ++i) {
		sil_symbol_match_v2_t *symbol = &result->symbols[i];
		free(symbol->matched_binary_id);
		free(symbol->matched_by);
		proto_symbol_free(symbol->symbol);
	}
	free(result->symbols);
	for (size_t i = 0; i < result->n_candidate_binary_ids; ++i) {
		free(result->candidate_binary_ids[i]);
	}
	free(result->candidate_binary_ids);
	free(result->model_version);
	free(result->index_version);
	memset(result, 0, sizeof(*result));
}

static void sil_capnp_share_result_fini(sil_share_result_t *result) {
	free(result->binary_id);
	free(result->model_version);
	free(result->index_version);
	memset(result, 0, sizeof(*result));
}

void sil_capnp_response_fini(sil_v2_response_t *response) {
	if (!response) {
		return;
	}
	switch (response->which) {
	case ResponseV2_message:
		free(response->text);
		break;
	case ResponseV2_serverInfo:
		sil_capnp_server_info_fini(&response->server_info);
		break;
	case ResponseV2_resolveResult:
		sil_capnp_resolve_result_fini(&response->resolve_result);
		break;
	case ResponseV2_shareResult:
		sil_capnp_share_result_fini(&response->share_result);
		break;
	default:
		break;
	}
	memset(response, 0, sizeof(*response));
}

void sil_capnp_debug_dump_program(const char *label, const sil_program_bundle_t *program) {
	if (!program) {
		return;
	}

	size_t ghidra = 0;
	size_t pseudo = 0;
	size_t none = 0;
	size_t other = 0;
	size_t pseudocode_bytes = 0;
	for (size_t i = 0; i < program->n_functions; ++i) {
		const sil_function_v2_t *function = &program->functions[i];
		if (function->pseudocode) {
			pseudocode_bytes += strlen(function->pseudocode);
		}
		if (!function->pseudocode_source || !strcmp(function->pseudocode_source, "none")) {
			none++;
		} else if (!strcmp(function->pseudocode_source, "ghidra")) {
			ghidra++;
		} else if (!strcmp(function->pseudocode_source, "pseudo")) {
			pseudo++;
		} else {
			other++;
		}
	}

	RZ_LOG_DEBUG(
		"silhouette: capnp %s bundle id=%s arch=%s bits=%u sections=%zu functions=%zu topk=%u pseudocode_bytes=%zu sources{ghidra=%zu pseudo=%zu none=%zu other=%zu}\n",
		sil_capnp_safe_text(label, "program"),
		sil_capnp_safe_text(program->binary_id, "-"),
		sil_capnp_safe_text(program->arch, "any"),
		program->bits,
		program->n_sections,
		program->n_functions,
		program->topk,
		pseudocode_bytes,
		ghidra,
		pseudo,
		none,
		other);
}

void sil_capnp_debug_dump_response(const char *label, const sil_v2_response_t *response) {
	if (!response) {
		return;
	}

	switch (response->which) {
	case ResponseV2_message:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u message=%s\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			sil_capnp_safe_text(response->text, "-"));
		break;
	case ResponseV2_serverInfo:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u server[min=%u max=%u keenhash=%s tls=%s model=%s index=%s]\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			response->server_info.min_version,
			response->server_info.max_version,
			response->server_info.keenhash_enabled ? "on" : "off",
			response->server_info.tls_required ? "required" : "optional",
			sil_capnp_safe_text(response->server_info.model_version, "-"),
			sil_capnp_safe_text(response->server_info.index_version, "-"));
		break;
	case ResponseV2_resolveResult:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u resolve[hints=%zu symbols=%zu candidates=%zu model=%s index=%s]\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			response->resolve_result.n_hints,
			response->resolve_result.n_symbols,
			response->resolve_result.n_candidate_binary_ids,
			sil_capnp_safe_text(response->resolve_result.model_version, "-"),
			sil_capnp_safe_text(response->resolve_result.index_version, "-"));
		break;
	case ResponseV2_shareResult:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u share[binary_id=%s ingested=%u candidates=%u model=%s index=%s]\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			sil_capnp_safe_text(response->share_result.binary_id, "-"),
			response->share_result.ingested_functions,
			response->share_result.candidate_count,
			sil_capnp_safe_text(response->share_result.model_version, "-"),
			sil_capnp_safe_text(response->share_result.index_version, "-"));
		break;
	default:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u which=%u\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			response->which);
		break;
	}
}
