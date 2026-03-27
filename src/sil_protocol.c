// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_protocol.c
 * Silhouette Cap'n Proto protocol functions.
 */

#include "sil_protocol.h"
#include <limits.h>

#define SIL_HEADER_SIZE (sizeof(ut32))
#define SIL_CAPNP_MAGIC "SILC"
#define SIL_SOCKET_WRITE_CHUNK 1400

static bool sil_socket_write_all(RzSocket *socket, const ut8 *buffer, size_t size) {
	if (!socket) {
		return false;
	}
	for (size_t offset = 0; offset < size;) {
		size_t chunk = RZ_MIN(size - offset, (size_t)SIL_SOCKET_WRITE_CHUNK);
		int written = rz_socket_write(socket, (void *)(buffer + offset), (int)chunk);
		if (written != (int)chunk) {
			return false;
		}
		offset += chunk;
	}
	return true;
}

static bool sil_socket_read_all(RzSocket *socket, ut8 *buffer, size_t size) {
	if (!socket) {
		return false;
	}
	if (size < 1) {
		return true;
	}
	return rz_socket_read_block(socket, buffer, (int)size) == (int)size;
}

static bool sil_capnp_ptr_valid(capn_ptr ptr) {
	return ptr.type != CAPN_NULL && ptr.seg != NULL;
}

static bool sil_capnp_list_size_valid(size_t size) {
	return size <= (size_t)INT_MAX;
}

static capn_text sil_capnp_text(const char *text) {
	capn_text out = { 0 };
	out.str = text ? text : "";
	out.len = (int)strlen(out.str);
	out.seg = NULL;
	return out;
}

static char *sil_capnp_strdup(capn_text text) {
	size_t size = text.len > 0 ? (size_t)text.len : 0;
	char *dup = calloc(sizeof(char), size + 1);
	if (!dup) {
		return NULL;
	}
	if (size > 0 && text.str) {
		memcpy(dup, text.str, size);
	}
	return dup;
}

static bool sil_capnp_data_new(struct capn_segment *seg, const ut8 *data, size_t size, capn_data *out) {
	if (!out) {
		return false;
	}
	memset(out, 0, sizeof(*out));
	if (!data || size < 1) {
		return true;
	}
	if (!sil_capnp_list_size_valid(size)) {
		return false;
	}

	capn_list8 list = capn_new_list8(seg, (int)size);
	if (!sil_capnp_ptr_valid(list.p)) {
		return false;
	}
	if (capn_setv8(list, 0, data, (int)size) != (int)size) {
		return false;
	}

	out->p = list.p;
	return true;
}

static bool sil_protocol_capnp_send_frame(RzSocket *socket, const ut8 *body, size_t body_size) {
	ut32 total_size = (ut32)(strlen(SIL_CAPNP_MAGIC) + body_size);
	ut8 header[SIL_HEADER_SIZE] = { 0 };
	rz_write_be32(header, total_size);

	if (!sil_socket_write_all(socket, header, sizeof(header)) ||
		!sil_socket_write_all(socket, (const ut8 *)SIL_CAPNP_MAGIC, strlen(SIL_CAPNP_MAGIC)) ||
		!sil_socket_write_all(socket, body, body_size)) {
		return false;
	}
	rz_socket_flush(socket);
	return true;
}

static bool sil_protocol_capnp_try_encode(RzSocket *socket, struct capn *ctx, bool packed, size_t payload_cap) {
	ut8 *payload = payload_cap > 0 ? malloc(payload_cap) : NULL;
	if (payload_cap > 0 && !payload) {
		return false;
	}

	int64_t written = packed ? capn_write_mem(ctx, payload, payload_cap, 1) : capn_write_mem(ctx, payload, payload_cap, 0);
	if (written <= 0 || (size_t)written > payload_cap) {
		free(payload);
		return false;
	}

	bool ok = sil_protocol_capnp_send_frame(socket, payload, (size_t)written);
	free(payload);
	return ok;
}

static bool sil_protocol_capnp_send_ctx(RzSocket *socket, struct capn *ctx) {
	int64_t message_max = capn_size(ctx);
	if (message_max <= 0) {
		return false;
	}

	for (int packed = 1; packed >= 0; packed--) {
		size_t payload_cap = packed ? (size_t)message_max + ((size_t)message_max / 8U) + 64U : (size_t)message_max;
		size_t max_attempts = packed ? 4U : 1U;
		for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
			if (sil_protocol_capnp_try_encode(socket, ctx, packed != 0, payload_cap)) {
				return true;
			}
			if (!packed || payload_cap > (SIZE_MAX / 2U)) {
				break;
			}
			payload_cap *= 2U;
		}
	}

	RZ_LOG_ERROR("silhouette: failed to serialize capnp message\n");
	return false;
}

static SilProgramBundle_ptr sil_capnp_program_new(struct capn_segment *seg, const sil_program_bundle_t *program) {
	SilProgramBundle_ptr out = new_SilProgramBundle(seg);
	if (!sil_capnp_ptr_valid(out.p) || !program) {
		return out;
	}

	SilProgramBundle_set_binaryType(out, sil_capnp_text(program->binary_type));
	SilProgramBundle_set_os(out, sil_capnp_text(program->os));
	SilProgramBundle_set_arch(out, sil_capnp_text(program->arch));
	SilProgramBundle_set_bits(out, program->bits);
	SilProgramBundle_set_binaryId(out, sil_capnp_text(program->binary_id));

	if (program->n_sections > 0) {
		if (!sil_capnp_list_size_valid(program->n_sections)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		SilSectionHash_list sections = new_SilSectionHash_list(seg, (int)program->n_sections);
		if (!sil_capnp_ptr_valid(sections.p)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		for (size_t i = 0; i < program->n_sections; ++i) {
			const sil_section_t *section = &program->sections[i];
			struct SilSectionHash item = { 0 };
			item.name = sil_capnp_text(section->name);
			item.size = section->size;
			item.paddr = section->paddr;
			if (!sil_capnp_data_new(seg, section->digest, section->digest_size, &item.digest)) {
				out.p.type = CAPN_NULL;
				return out;
			}
			set_SilSectionHash(&item, sections, (int)i);
		}
		SilProgramBundle_set_sections(out, sections);
	}

	if (program->n_functions > 0) {
		if (!sil_capnp_list_size_valid(program->n_functions)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		SilFunctionBundle_list functions = new_SilFunctionBundle_list(seg, (int)program->n_functions);
		if (!sil_capnp_ptr_valid(functions.p)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		for (size_t i = 0; i < program->n_functions; ++i) {
			const sil_function_t *function = &program->functions[i];
			struct SilFunctionBundle item = { 0 };
			item.addr = function->addr;
			item.size = function->size;
			item.bits = function->bits;
			item.arch = sil_capnp_text(function->arch);
			item.length = function->length;
			if (!sil_capnp_data_new(seg, function->digest, function->digest_size, &item.digest)) {
				out.p.type = CAPN_NULL;
				return out;
			}
			item.sectionName = sil_capnp_text(function->section_name);
			item.sectionPaddr = function->section_paddr;
			item.sectionOffset = function->section_offset;
			item.name = sil_capnp_text(function->name);
			item.signature = sil_capnp_text(function->signature);
			item.callconv = sil_capnp_text(function->callconv);
			set_SilFunctionBundle(&item, functions, (int)i);
		}
		SilProgramBundle_set_functions(out, functions);
	}

	return out;
}

bool sil_protocol_ping_send(RzSocket *socket, const char *psk) {
	struct capn ctx;
	capn_init_malloc(&ctx);
	SilPing_ptr ping = new_SilPing(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(ping.p)) {
		capn_free(&ctx);
		return false;
	}

	struct SilRequest request = { 0 };
	request.psk = sil_capnp_text(psk);
	request.version = RZ_SIL_PROTOCOL_VERSION;
	request.route = SilRoute_ping;
	request.which = SilRequest_ping;
	request.ping = ping;

	SilRequest_ptr reqp = new_SilRequest(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(reqp.p)) {
		capn_free(&ctx);
		return false;
	}
	write_SilRequest(&request, reqp);
	if (capn_setp(capn_root(&ctx), 0, reqp.p) != 0) {
		capn_free(&ctx);
		return false;
	}
	bool ok = sil_protocol_capnp_send_ctx(socket, &ctx);
	capn_free(&ctx);
	return ok;
}

bool sil_protocol_resolve_program_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program) {
	struct capn ctx;
	capn_init_malloc(&ctx);
	SilProgramBundle_ptr prog = sil_capnp_program_new(capn_root(&ctx).seg, program);
	if (!sil_capnp_ptr_valid(prog.p)) {
		capn_free(&ctx);
		return false;
	}
	SilResolveProgram_ptr resolve = new_SilResolveProgram(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(resolve.p)) {
		capn_free(&ctx);
		return false;
	}
	SilResolveProgram_set_program(resolve, prog);

	struct SilRequest request = { 0 };
	request.psk = sil_capnp_text(psk);
	request.version = RZ_SIL_PROTOCOL_VERSION;
	request.route = SilRoute_resolveProgram;
	request.which = SilRequest_resolveProgram;
	request.resolveProgram = resolve;

	SilRequest_ptr reqp = new_SilRequest(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(reqp.p)) {
		capn_free(&ctx);
		return false;
	}
	write_SilRequest(&request, reqp);
	if (capn_setp(capn_root(&ctx), 0, reqp.p) != 0) {
		capn_free(&ctx);
		return false;
	}
	bool ok = sil_protocol_capnp_send_ctx(socket, &ctx);
	capn_free(&ctx);
	return ok;
}

bool sil_protocol_share_program_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program) {
	struct capn ctx;
	capn_init_malloc(&ctx);
	SilProgramBundle_ptr prog = sil_capnp_program_new(capn_root(&ctx).seg, program);
	if (!sil_capnp_ptr_valid(prog.p)) {
		capn_free(&ctx);
		return false;
	}
	SilShareProgram_ptr share = new_SilShareProgram(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(share.p)) {
		capn_free(&ctx);
		return false;
	}
	SilShareProgram_set_program(share, prog);

	struct SilRequest request = { 0 };
	request.psk = sil_capnp_text(psk);
	request.version = RZ_SIL_PROTOCOL_VERSION;
	request.route = SilRoute_shareProgram;
	request.which = SilRequest_shareProgram;
	request.shareProgram = share;

	SilRequest_ptr reqp = new_SilRequest(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(reqp.p)) {
		capn_free(&ctx);
		return false;
	}
	write_SilRequest(&request, reqp);
	if (capn_setp(capn_root(&ctx), 0, reqp.p) != 0) {
		capn_free(&ctx);
		return false;
	}
	bool ok = sil_protocol_capnp_send_ctx(socket, &ctx);
	capn_free(&ctx);
	return ok;
}

bool sil_protocol_response_recv(RzSocket *socket, sil_response_t *response) {
	ut8 header[SIL_HEADER_SIZE] = { 0 };
	memset(response, 0, sizeof(*response));

	if (!sil_socket_read_all(socket, header, sizeof(header))) {
		RZ_LOG_ERROR("silhouette: failed to read capnp response packed size\n");
		return false;
	}

	ut32 size = rz_read_be32(header);
	if (size < strlen(SIL_CAPNP_MAGIC)) {
		RZ_LOG_ERROR("silhouette: invalid capnp response size %u\n", size);
		return false;
	}

	ut8 *buffer = malloc(size);
	if (!buffer) {
		RZ_LOG_ERROR("silhouette: failed to allocate %u bytes for capnp response\n", size);
		return false;
	}
	if (!sil_socket_read_all(socket, buffer, size)) {
		RZ_LOG_ERROR("silhouette: failed to read %u bytes of capnp response body\n", size);
		free(buffer);
		return false;
	}
	if (memcmp(buffer, SIL_CAPNP_MAGIC, strlen(SIL_CAPNP_MAGIC))) {
		RZ_LOG_ERROR("silhouette: capnp response magic mismatch\n");
		free(buffer);
		return false;
	}

	struct capn ctx;
	if (capn_init_mem(&ctx, buffer + strlen(SIL_CAPNP_MAGIC), size - strlen(SIL_CAPNP_MAGIC), 1) != 0) {
		RZ_LOG_ERROR("silhouette: failed to initialize capnp response decoder (%u bytes)\n", size);
		free(buffer);
		return false;
	}

	SilResponse_ptr root = { 0 };
	root.p = capn_getp(capn_root(&ctx), 0, 1);
	struct SilResponse message = { 0 };
	read_SilResponse(&message, root);

	response->status = message.status;
	response->which = message.which;

	switch (message.which) {
	case SilResponse_message: {
		struct SilMessage text = { 0 };
		read_SilMessage(&text, message.message);
		response->text = sil_capnp_strdup(text.text);
		break;
	}
	case SilResponse_serverInfo: {
		struct SilServerInfo info = { 0 };
		read_SilServerInfo(&info, message.serverInfo);
		response->server_info.version = info.version;
		response->server_info.tls_required = info.tlsRequired;
		break;
	}
	case SilResponse_resolveResult: {
		struct SilResolveResult result = { 0 };
		read_SilResolveResult(&result, message.resolveResult);
		response->resolve_result.n_hints = capn_len(result.hints);
		response->resolve_result.hints = calloc(sizeof(sil_hint_t), response->resolve_result.n_hints);
		if (response->resolve_result.n_hints > 0 && !response->resolve_result.hints) {
			capn_free(&ctx);
			free(buffer);
			return false;
		}
		for (size_t i = 0; i < response->resolve_result.n_hints; ++i) {
			struct SilHint hint = { 0 };
			get_SilHint(&hint, result.hints, (int)i);
			response->resolve_result.hints[i].bits = hint.bits;
			response->resolve_result.hints[i].offset = hint.offset;
		}

		response->resolve_result.n_symbols = capn_len(result.symbols);
		response->resolve_result.symbols = calloc(sizeof(sil_symbol_match_t), response->resolve_result.n_symbols);
		if (response->resolve_result.n_symbols > 0 && !response->resolve_result.symbols) {
			capn_free(&ctx);
			free(buffer);
			return false;
		}
		for (size_t i = 0; i < response->resolve_result.n_symbols; ++i) {
			struct SilSymbolMatch match = { 0 };
			struct SilSymbol symbol = { 0 };
			get_SilSymbolMatch(&match, result.symbols, (int)i);
			read_SilSymbol(&symbol, match.symbol);
			response->resolve_result.symbols[i].addr = match.addr;
			response->resolve_result.symbols[i].exact = match.exact;
			response->resolve_result.symbols[i].matched_binary_id = sil_capnp_strdup(match.matchedBinaryId);
			response->resolve_result.symbols[i].matched_by = sil_capnp_strdup(match.matchedBy);
			response->resolve_result.symbols[i].offset = match.offset;
			response->resolve_result.symbols[i].size = match.size;
			response->resolve_result.symbols[i].symbol = sil_symbol_new(
				symbol.name.str ? symbol.name.str : NULL,
				symbol.signature.str ? symbol.signature.str : NULL,
				symbol.callconv.str ? symbol.callconv.str : NULL,
				symbol.bits);
		}
		break;
	}
	case SilResponse_shareResult: {
		struct SilShareResult result = { 0 };
		read_SilShareResult(&result, message.shareResult);
		response->share_result.binary_id = sil_capnp_strdup(result.binaryId);
		break;
	}
	default:
		break;
	}

	capn_free(&ctx);
	free(buffer);
	return true;
}
