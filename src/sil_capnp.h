// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SIL_CAPNP_H
#define SIL_CAPNP_H

#include "sil.h"
#include "service.capnp.h"
#include <capnp_c.h>

typedef struct {
	ut8 *data;
	size_t len;
} sil_blob_t;

typedef struct {
	char *name;
	char *signature;
	char *callconv;
	ut32 bits;
} Symbol;

typedef struct {
	char *arch;
	ut32 bits;
	ut32 length;
	sil_blob_t digest;
} Signature;

typedef struct {
	ut32 size;
	ut64 paddr;
	sil_blob_t digest;
} SectionHash;

typedef struct {
	char *name;
	ut32 size;
	ut64 paddr;
	ut8 *digest;
	size_t digest_size;
} sil_section_t;

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
	char *name;
	char *signature;
	char *callconv;
} sil_function_t;

typedef struct {
	char *binary_type;
	char *os;
	char *arch;
	ut32 bits;
	char *binary_id;
	sil_section_t *sections;
	size_t n_sections;
	sil_function_t *functions;
	size_t n_functions;
} sil_program_bundle_t;

typedef struct {
	ut32 bits;
	ut64 offset;
} sil_hint_t;

typedef struct {
	ut64 addr;
	Symbol *symbol;
	float confidence;
	bool exact;
	char *matched_binary_id;
	char *matched_by;
	ut64 offset;
	ut32 size;
} sil_symbol_match_t;

typedef struct {
	ut32 version;
	bool tls_required;
} sil_server_info_t;

typedef struct {
	sil_hint_t *hints;
	size_t n_hints;
	sil_symbol_match_t *symbols;
	size_t n_symbols;
} sil_resolve_result_t;

typedef struct {
	char *binary_id;
} sil_share_result_t;

typedef struct {
	enum SilStatus status;
	enum SilResponse_which which;
	union {
		char *text;
		sil_server_info_t server_info;
		sil_resolve_result_t resolve_result;
		sil_share_result_t share_result;
	};
} sil_response_t;

Symbol *sil_symbol_new(const char *name, const char *signature, const char *callconv, ut32 bits);
void sil_symbol_free(Symbol *symbol);
void sil_signature_free(Signature *signature);
void sil_section_hash_free(SectionHash *section);

void sil_capnp_program_fini(sil_program_bundle_t *program);
void sil_capnp_response_fini(sil_response_t *response);
void sil_capnp_debug_dump_program(const char *label, const sil_program_bundle_t *program);
void sil_capnp_debug_dump_response(const char *label, const sil_response_t *response);

bool sil_protocol_ping_send(RzSocket *socket, const char *psk);
bool sil_protocol_resolve_program_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program);
bool sil_protocol_share_program_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program);
bool sil_protocol_response_recv(RzSocket *socket, sil_response_t *response);

#endif /* SIL_CAPNP_H */
