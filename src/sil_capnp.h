// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SIL_CAPNP_H
#define SIL_CAPNP_H

#include "sil.h"
#include "service.pb-c.h"
#include "service.capnp.h"
#include <capnp_c.h>

typedef struct {
	char *name;
	ut32 size;
	ut64 paddr;
	ut8 *digest;
	size_t digest_size;
} sil_section_v2_t;

typedef struct {
	ut64 addr;
	ut32 size;
	ut32 bits;
	char *arch;
	ut32 length;
	ut8 *digest;
	size_t digest_size;
	char *section_name;
	ut64 section_paddr;
	ut64 section_offset;
	ut32 loc;
	ut32 nos;
	char *pseudocode;
	char *pseudocode_source;
	ut64 *calls;
	size_t n_calls;
	char *name;
	char *signature;
	char *callconv;
} sil_function_v2_t;

typedef struct {
	char *binary_type;
	char *os;
	char *arch;
	ut32 bits;
	char *binary_id;
	sil_section_v2_t *sections;
	size_t n_sections;
	sil_function_v2_t *functions;
	size_t n_functions;
	ut32 topk;
} sil_program_bundle_t;

typedef struct {
	ut32 bits;
	ut64 offset;
	float confidence;
	char *matched_binary_id;
} sil_hint_v2_t;

typedef struct {
	ut64 addr;
	Symbol *symbol;
	float confidence;
	bool exact;
	char *matched_binary_id;
	char *matched_by;
	ut64 offset;
	ut32 size;
} sil_symbol_match_v2_t;

typedef struct {
	ut32 min_version;
	ut32 max_version;
	bool keenhash_enabled;
	bool decompiler_required;
	bool tls_required;
	char *model_version;
	char *index_version;
} sil_server_info_t;

typedef struct {
	sil_hint_v2_t *hints;
	size_t n_hints;
	sil_symbol_match_v2_t *symbols;
	size_t n_symbols;
	char **candidate_binary_ids;
	size_t n_candidate_binary_ids;
	char *model_version;
	char *index_version;
} sil_resolve_result_t;

typedef struct {
	char *binary_id;
	ut32 ingested_functions;
	ut32 candidate_count;
	char *model_version;
	char *index_version;
} sil_share_result_t;

typedef struct {
	enum StatusV2 status;
	enum ResponseV2_which which;
	union {
		char *text;
		sil_server_info_t server_info;
		sil_resolve_result_t resolve_result;
		sil_share_result_t share_result;
	};
} sil_v2_response_t;

void sil_capnp_program_fini(sil_program_bundle_t *program);
void sil_capnp_response_fini(sil_v2_response_t *response);
void sil_capnp_debug_dump_program(const char *label, const sil_program_bundle_t *program);
void sil_capnp_debug_dump_response(const char *label, const sil_v2_response_t *response);

bool sil_protocol_ping_v2_send(RzSocket *socket, const char *psk);
bool sil_protocol_resolve_program_v2_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program);
bool sil_protocol_share_program_v2_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program);
bool sil_protocol_response_v2_recv(RzSocket *socket, sil_v2_response_t *response);

#endif /* SIL_CAPNP_H */
