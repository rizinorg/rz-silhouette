// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sil_capnp.h"
#include "sil_helpers.h"

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
