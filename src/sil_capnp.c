// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sil_capnp.h"

static const char *sil_capnp_safe_text(const char *text, const char *fallback) {
	return RZ_STR_ISNOTEMPTY(text) ? text : fallback;
}

Symbol *sil_symbol_new(const char *name, const char *signature, const char *callconv, ut32 bits) {
	Symbol *symbol = RZ_NEW0(Symbol);
	if (!symbol) {
		return NULL;
	}
	symbol->name = name ? strdup(name) : NULL;
	symbol->signature = signature ? strdup(signature) : NULL;
	symbol->callconv = callconv ? strdup(callconv) : NULL;
	symbol->bits = bits;
	if ((name && !symbol->name) || (signature && !symbol->signature) || (callconv && !symbol->callconv)) {
		sil_symbol_free(symbol);
		return NULL;
	}
	return symbol;
}

void sil_symbol_free(Symbol *symbol) {
	if (!symbol) {
		return;
	}
	free(symbol->name);
	free(symbol->signature);
	free(symbol->callconv);
	free(symbol);
}

void sil_signature_free(Signature *signature) {
	if (!signature) {
		return;
	}
	free(signature->arch);
	free(signature->digest.data);
	free(signature);
}

void sil_section_hash_free(SectionHash *section) {
	if (!section) {
		return;
	}
	free(section->digest.data);
	free(section);
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
		sil_function_t *function = &program->functions[i];
		free(function->arch);
		free(function->digest);
		free(function->section_name);
		free(function->name);
		free(function->signature);
		free(function->callconv);
	}
	free(program->functions);
	memset(program, 0, sizeof(*program));
}

static void sil_capnp_server_info_fini(sil_server_info_t *info) {
	memset(info, 0, sizeof(*info));
}

static void sil_capnp_resolve_result_fini(sil_resolve_result_t *result) {
	free(result->hints);
	for (size_t i = 0; i < result->n_symbols; ++i) {
		sil_symbol_match_t *symbol = &result->symbols[i];
		free(symbol->matched_binary_id);
		free(symbol->matched_by);
		sil_symbol_free(symbol->symbol);
	}
	free(result->symbols);
	memset(result, 0, sizeof(*result));
}

static void sil_capnp_share_result_fini(sil_share_result_t *result) {
	free(result->binary_id);
	memset(result, 0, sizeof(*result));
}

void sil_capnp_response_fini(sil_response_t *response) {
	if (!response) {
		return;
	}
	switch (response->which) {
	case SilResponse_message:
		free(response->text);
		break;
	case SilResponse_serverInfo:
		sil_capnp_server_info_fini(&response->server_info);
		break;
	case SilResponse_resolveResult:
		sil_capnp_resolve_result_fini(&response->resolve_result);
		break;
	case SilResponse_shareResult:
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

	RZ_LOG_DEBUG(
		"silhouette: capnp %s bundle id=%s arch=%s bits=%u sections=%zu functions=%zu\n",
		sil_capnp_safe_text(label, "program"),
		sil_capnp_safe_text(program->binary_id, "-"),
		sil_capnp_safe_text(program->arch, "any"),
		program->bits,
		program->n_sections,
		program->n_functions);
}

void sil_capnp_debug_dump_response(const char *label, const sil_response_t *response) {
	if (!response) {
		return;
	}

	switch (response->which) {
	case SilResponse_message:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u message=%s\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			sil_capnp_safe_text(response->text, "-"));
		break;
	case SilResponse_serverInfo:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u server[version=%u tls=%s]\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			response->server_info.version,
			response->server_info.tls_required ? "required" : "optional");
		break;
	case SilResponse_resolveResult:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u resolve[hints=%zu symbols=%zu]\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			response->resolve_result.n_hints,
			response->resolve_result.n_symbols);
		break;
	case SilResponse_shareResult:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u share[binary_id=%s]\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			sil_capnp_safe_text(response->share_result.binary_id, "-"));
		break;
	default:
		RZ_LOG_DEBUG("silhouette: capnp %s response status=%u which=%u\n",
			sil_capnp_safe_text(label, "response"),
			response->status,
			response->which);
		break;
	}
}
