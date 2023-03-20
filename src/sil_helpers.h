// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SIL_HELPERS_H
#define SIL_HELPERS_H

#include "sil.h"
#include "service.pb-c.h"
#include <protobuf-c/protobuf-c.h>

char *sil_to_lower_dup(const char *original, const char *def_string);

/* Protobuf helpers */
void proto_section_hash_free(SectionHash *message);
SectionHash *proto_section_hash_new(ut32 size, ut8 *digest, size_t digest_size);

void proto_share_section_free(ShareSection *message);
ShareSection *proto_share_section_new(const char *name, SectionHash *section, size_t reserve_hints);
void proto_share_section_hint_add(ShareSection *message, ut64 offset, ut32 bits);

void proto_symbol_free(Symbol *message);
Symbol *proto_symbol_new(const char *name, const char *signature, const char *callconv, ut32 bits);

void proto_signature_free(Signature *message);
Signature *proto_signature_new(const char *arch, ut32 bits, ut32 length, ut8 *digest, size_t digest_size);

void proto_binary_free(Binary *message);
Binary *proto_binary_new(const char *type, const char *os, ut32 reserve_sections);
void proto_binary_section_hash_add(Binary *message, SectionHash *element);

void proto_share_symbol_free(ShareSymbol *message);
ShareSymbol *proto_share_symbol_new(Symbol *symbol, Signature *signature);

void proto_share_bin_fini(ShareBin *message);
bool proto_share_bin_init(ShareBin *message, const char *type, const char *os, size_t reserve_sections, size_t reserve_symbols);
void proto_share_bin_share_section_add(ShareBin *message, ShareSection *element);
void proto_share_bin_share_symbol_add(ShareBin *message, ShareSymbol *element);

void proto_request_free(Request *message);
Request *proto_request_new(const char *psk, Route route);

#define proto_request_ping_new(psk)      proto_request_new(psk, ROUTE__PING)
#define proto_request_binary_new(psk)    proto_request_new(psk, ROUTE__BINARY)
#define proto_request_signature_new(psk) proto_request_new(psk, ROUTE__SIGNATURE)
#define proto_request_share_bin_new(psk) proto_request_new(psk, ROUTE__SHARE_BIN)

#endif /* SIL_HELPERS_H */
