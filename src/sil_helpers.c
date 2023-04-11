// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_helper.c
 * Contains the helpers to interact with the protoc api.
 */

#include "sil_helpers.h"
#include "sil_const.h"

char *sil_to_lower_dup(const char *original, const char *def_string) {
	const char *string = RZ_STR_ISEMPTY(original) ? def_string : original;
	size_t length = strlen(string);
	char *s = calloc(sizeof(char), length + 1);
	for (size_t i = 0, j = 0; i < length; ++i) {
		if (!IS_ALPHANUM(string[i])) {
			continue;
		}
		s[j] = tolower(string[i]);
		j++;
	}
	if (strlen(s) < 1) {
		return strdup(def_string);
	}
	return s;
}

void proto_section_hash_free(SectionHash *message) {
	if (!message) {
		return;
	}
	free(message->digest.data);
	free(message);
}

SectionHash *proto_section_hash_new(ut32 size, ut64 paddr, ut8 *digest, size_t digest_size) {
	SectionHash *message = RZ_NEW0(SectionHash);
	if (!message) {
		return NULL;
	}
	section_hash__init(message);

	message->size = size;
	message->paddr = paddr;
	message->digest.data = digest;
	message->digest.len = digest_size;
	return message;
}

void proto_share_section_free(ShareSection *message) {
	if (!message) {
		return;
	}
	free(message->name);
	proto_section_hash_free(message->section);
	for (size_t i = 0; i < message->n_hints; ++i) {
		free(message->hints[i]);
	}
	free(message->hints);
	free(message);
}

ShareSection *proto_share_section_new(const char *name, SectionHash *section, size_t reserve_hints) {
	ShareSection *message = RZ_NEW0(ShareSection);
	if (!message) {
		return NULL;
	}
	share_section__init(message);

	if (!(message->hints = calloc(sizeof(Hint *), reserve_hints))) {
		free(message);
		return NULL;
	}

	message->name = name ? strdup(name) : NULL;
	message->section = section;
	return message;
}

void proto_share_section_hint_add(ShareSection *message, ut64 offset, ut32 bits) {
	Hint *element = RZ_NEW0(Hint);
	if (!element) {
		return;
	}
	hint__init(element);

	element->offset = offset;
	element->bits = bits;
	message->hints[message->n_hints] = element;
	message->n_hints++;
}

void proto_symbol_free(Symbol *message) {
	if (!message) {
		return;
	}
	free(message->name);
	free(message->signature);
	free(message->callconv);
	free(message);
}

Symbol *proto_symbol_new(const char *name, const char *signature, const char *callconv, ut32 bits) {
	Symbol *message = RZ_NEW0(Symbol);
	if (!message) {
		return NULL;
	}
	symbol__init(message);

	message->name = name ? strdup(name) : NULL;
	message->signature = signature ? strdup(signature) : NULL;
	message->callconv = callconv ? strdup(callconv) : NULL;
	message->bits = bits;
	return message;
}

void proto_signature_free(Signature *message) {
	if (!message) {
		return;
	}
	free(message->arch);
	free(message->digest.data);
	free(message);
}

Signature *proto_signature_new(const char *arch, ut32 bits, ut32 length, ut8 *digest, size_t digest_size) {
	Signature *message = RZ_NEW0(Signature);
	if (!message) {
		return NULL;
	}
	signature__init(message);

	message->arch = sil_to_lower_dup(arch, "any");
	message->bits = bits;
	message->length = length;
	message->digest.data = digest;
	message->digest.len = digest_size;
	return message;
}

void proto_binary_free(Binary *message) {
	if (!message) {
		return;
	}
	free(message->type);
	free(message->os);
	for (size_t i = 0; i < message->n_sections; ++i) {
		proto_section_hash_free(message->sections[i]);
	}
	free(message->sections);
	free(message);
}

Binary *proto_binary_new(const char *type, const char *os, ut32 reserve_sections) {
	Binary *message = RZ_NEW0(Binary);
	if (!message) {
		return NULL;
	}
	binary__init(message);

	if (!(message->sections = calloc(sizeof(SectionHash *), reserve_sections))) {
		free(message);
		return NULL;
	}

	message->type = sil_to_lower_dup(type, "any");
	message->os = sil_to_lower_dup(os, "any");
	return message;
}

void proto_binary_section_hash_add(Binary *message, SectionHash *element) {
	message->sections[message->n_sections] = element;
	message->n_sections++;
}

void proto_share_symbol_free(ShareSymbol *message) {
	if (!message) {
		return;
	}
	proto_symbol_free(message->symbol);
	proto_signature_free(message->signature);
	free(message);
}

ShareSymbol *proto_share_symbol_new(Symbol *symbol, Signature *signature) {
	ShareSymbol *message = RZ_NEW0(ShareSymbol);
	if (!message) {
		return NULL;
	}
	share_symbol__init(message);

	message->symbol = symbol;
	message->signature = signature;
	return message;
}

void proto_share_bin_fini(ShareBin *message) {
	for (size_t i = 0; i < message->n_sections; ++i) {
		proto_share_section_free(message->sections[i]);
	}
	for (size_t i = 0; i < message->n_symbols; ++i) {
		proto_share_symbol_free(message->symbols[i]);
	}
	free(message->sections);
	free(message->symbols);
	free(message->type);
	free(message->os);
}

bool proto_share_bin_init(ShareBin *message, const char *type, const char *os, size_t reserve_sections, size_t reserve_symbols) {
	share_bin__init(message);

	if (!(message->sections = calloc(sizeof(ShareSection *), reserve_sections)) ||
		!(message->symbols = calloc(sizeof(ShareSymbol *), reserve_symbols))) {
		free(message->sections);
		free(message->symbols);
		message->sections = NULL;
		message->symbols = NULL;
		return false;
	}

	message->type = sil_to_lower_dup(type, "any");
	message->os = sil_to_lower_dup(os, "any");
	return true;
}

void proto_share_bin_share_section_add(ShareBin *message, ShareSection *element) {
	message->sections[message->n_sections] = element;
	message->n_sections++;
}

void proto_share_bin_share_symbol_add(ShareBin *message, ShareSymbol *element) {
	message->symbols[message->n_symbols] = element;
	message->n_symbols++;
}

void proto_request_free(Request *request) {
	if (!request) {
		return;
	}
	free(request->psk);
	free(request->message.data);
	free(request);
}

Request *proto_request_new(const char *psk, Route route) {
	Request *request = RZ_NEW0(Request);
	if (!request) {
		return NULL;
	}
	request__init(request);

	request->psk = psk ? strdup(psk) : NULL;
	request->version = RZ_SIL_VERSION;
	request->route = route;
	return request;
}
