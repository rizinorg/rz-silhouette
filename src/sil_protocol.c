// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_protocol.c
 * Silhouette protocol functions.
 */

#include "sil_protocol.h"
#include <limits.h>

#define SIL_HEADER_SIZE (sizeof(ut32))
#define SIL_CAPNP_MAGIC "SIL2"
#define SIL_SOCKET_WRITE_CHUNK 1400

static bool sil_socket_write_all(RzSocket *socket, const ut8 *buffer, size_t size) {
	if (!socket) {
		return false;
	}
	for (size_t offset = 0; offset < size;) {
		/*
		 * rz_socket_write() internally slices large writes and reports only the
		 * last chunk length on success. Keep each call below that threshold so
		 * the caller can account for progress correctly.
		 */
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

static bool sil_protocol_request_send(RzSocket *socket, Request *request) {
	size_t size = request__get_packed_size(request);
	ut8 *buffer = malloc(size + SIL_HEADER_SIZE);
	if (!buffer) {
		RZ_LOG_ERROR("silhouette: failed to allocate request packed bytes\n");
		proto_request_free(request);
		return false;
	}

	rz_write_be32(buffer, size);
	request__pack(request, buffer + SIL_HEADER_SIZE);
	proto_request_free(request);

	bool written = sil_socket_write_all(socket, buffer, size + SIL_HEADER_SIZE);
	rz_socket_flush(socket);
	free(buffer);
	return written;
}

bool sil_protocol_response_recv(RzSocket *socket, Status *status, void **message) {
	ut8 header[SIL_HEADER_SIZE] = { 0 };
	if (!sil_socket_read_all(socket, header, sizeof(header))) {
		RZ_LOG_ERROR("silhouette: failed to read response packed size\n");
		return false;
	}

	ut32 size = rz_read_be32(header);
	ut8 *buffer = size > 0 ? malloc(size) : NULL;
	if (!buffer) {
		RZ_LOG_ERROR("silhouette: failed to allocate response packed bytes\n");
		return false;
	}

	if (!sil_socket_read_all(socket, buffer, size)) {
		RZ_LOG_ERROR("silhouette: failed to read packed bytes from the server\n");
		free(buffer);
		return false;
	}

	Response *response = response__unpack(NULL, size, buffer);
	free(buffer);
	if (!response) {
		RZ_LOG_ERROR("silhouette: failed to decode the response from the server\n");
		return false;
	}

	*status = response->status;

	switch (response->status) {
	case STATUS__INTERNAL_ERROR:
	case STATUS__CLIENT_NOT_AUTHORIZED:
	case STATUS__VERSION_MISMATCH:
	case STATUS__SHARE_WAS_SUCCESSFUL:
		*status = response->status;
		break;
	case STATUS__MESSAGE:
		if (response->message.data) {
			*message = message__unpack(NULL, response->message.len, response->message.data);
		}
		break;
	case STATUS__HINTS:
		if (response->message.data) {
			*message = match_hints__unpack(NULL, response->message.len, response->message.data);
		}
		break;
	case STATUS__SYMBOL:
		if (response->message.data) {
			*message = symbol__unpack(NULL, response->message.len, response->message.data);
		}
		break;
	default:
		break;
	}

	response__free_unpacked(response, NULL);
	return true;
}

bool sil_protocol_ping_send(RzSocket *socket, const char *psk) {
	Request *req = proto_request_ping_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate request ping\n");
		return false;
	}

	return sil_protocol_request_send(socket, req);
}

bool sil_protocol_binary_send(RzSocket *socket, const char *psk, Binary *binary) {
	size_t size = binary__get_packed_size(binary);
	ut8 *message = malloc(size);
	if (!message) {
		RZ_LOG_ERROR("silhouette: failed to allocate binary request bytes\n");
		return false;
	}

	Request *req = proto_request_binary_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate binary request\n");
		free(message);
		return false;
	}
	binary__pack(binary, message);

	req->message.data = message;
	req->message.len = size;
	return sil_protocol_request_send(socket, req);
}

bool sil_protocol_signature_send(RzSocket *socket, const char *psk, Signature *signature) {
	size_t size = signature__get_packed_size(signature);
	ut8 *message = malloc(size);
	if (!message) {
		RZ_LOG_ERROR("silhouette: failed to allocate signature request bytes\n");
		return false;
	}

	Request *req = proto_request_signature_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate signature request\n");
		free(message);
		return false;
	}
	signature__pack(signature, message);

	req->message.data = message;
	req->message.len = size;
	return sil_protocol_request_send(socket, req);
}

bool sil_protocol_share_bin_send(RzSocket *socket, const char *psk, ShareBin *sharebin) {
	size_t size = share_bin__get_packed_size(sharebin);
	ut8 *message = malloc(size);
	if (!message) {
		RZ_LOG_ERROR("silhouette: failed to allocate share request bytes\n");
		return false;
	}

	Request *req = proto_request_share_bin_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate share request\n");
		free(message);
		return false;
	}
	share_bin__pack(sharebin, message);

	req->message.data = message;
	req->message.len = size;
	return sil_protocol_request_send(socket, req);
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

static bool sil_capnp_u64_list_new(struct capn_segment *seg, const ut64 *data, size_t size, capn_list64 *out) {
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

	*out = capn_new_list64(seg, (int)size);
	if (!sil_capnp_ptr_valid(out->p)) {
		return false;
	}
	return capn_setv64(*out, 0, data, (int)size) == (int)size;
}

static bool sil_protocol_capnp_send_frame(RzSocket *socket, ut8 *buffer, size_t header_bytes, int64_t written) {
	if (written < 0 || (uint64_t)written > (uint64_t)(UINT32_MAX - strlen(SIL_CAPNP_MAGIC))) {
		return false;
	}

	ut32 body_size = (ut32)(strlen(SIL_CAPNP_MAGIC) + written);
	rz_write_be32(buffer, body_size);
	bool sent = sil_socket_write_all(socket, buffer, body_size + SIL_HEADER_SIZE);
	rz_socket_flush(socket);
	return sent;
}

static bool sil_protocol_capnp_try_encode(RzSocket *socket, struct capn *ctx, bool packed, size_t payload_cap, size_t header_bytes) {
	if (payload_cap > SIZE_MAX - header_bytes) {
		return false;
	}

	ut8 *buffer = malloc(header_bytes + payload_cap);
	if (!buffer) {
		return false;
	}

	memcpy(buffer + SIL_HEADER_SIZE, SIL_CAPNP_MAGIC, strlen(SIL_CAPNP_MAGIC));
	int64_t written = capn_write_mem(ctx, buffer + header_bytes, payload_cap, packed ? 1 : 0);
	if (written < 0) {
		free(buffer);
		return false;
	}

	bool sent = sil_protocol_capnp_send_frame(socket, buffer, header_bytes, written);
	free(buffer);
	return sent;
}

static bool sil_protocol_capnp_send_ctx(RzSocket *socket, struct capn *ctx) {
	int64_t message_max = capn_size(ctx);
	if (message_max <= 0) {
		return false;
	}

	size_t header_bytes = SIL_HEADER_SIZE + strlen(SIL_CAPNP_MAGIC);
	for (int packed = 1; packed >= 0; packed--) {
		size_t payload_cap = packed ? (size_t)message_max + ((size_t)message_max / 8U) + 64U : (size_t)message_max;
		size_t max_attempts = packed ? 4U : 1U;
		for (size_t attempt = 0; attempt < max_attempts; ++attempt) {
			if (sil_protocol_capnp_try_encode(socket, ctx, packed != 0, payload_cap, header_bytes)) {
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

static ProgramBundleV2_ptr sil_capnp_program_new(struct capn_segment *seg, const sil_program_bundle_t *program) {
	ProgramBundleV2_ptr out = new_ProgramBundleV2(seg);
	if (!sil_capnp_ptr_valid(out.p) || !program) {
		return out;
	}

	ProgramBundleV2_set_binaryType(out, sil_capnp_text(program->binary_type));
	ProgramBundleV2_set_os(out, sil_capnp_text(program->os));
	ProgramBundleV2_set_arch(out, sil_capnp_text(program->arch));
	ProgramBundleV2_set_bits(out, program->bits);
	ProgramBundleV2_set_binaryId(out, sil_capnp_text(program->binary_id));
	ProgramBundleV2_set_topk(out, program->topk);

	if (program->n_sections > 0) {
		if (!sil_capnp_list_size_valid(program->n_sections)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		SectionHashV2_list sections = new_SectionHashV2_list(seg, (int)program->n_sections);
		if (!sil_capnp_ptr_valid(sections.p)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		for (size_t i = 0; i < program->n_sections; ++i) {
			const sil_section_v2_t *section = &program->sections[i];
			struct SectionHashV2 item = { 0 };
			item.name = sil_capnp_text(section->name);
			item.size = section->size;
			item.paddr = section->paddr;
			if (!sil_capnp_data_new(seg, section->digest, section->digest_size, &item.digest)) {
				out.p.type = CAPN_NULL;
				return out;
			}
			set_SectionHashV2(&item, sections, (int)i);
		}
		ProgramBundleV2_set_sections(out, sections);
	}

	if (program->n_functions > 0) {
		if (!sil_capnp_list_size_valid(program->n_functions)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		FunctionBundleV2_list functions = new_FunctionBundleV2_list(seg, (int)program->n_functions);
		if (!sil_capnp_ptr_valid(functions.p)) {
			out.p.type = CAPN_NULL;
			return out;
		}
		for (size_t i = 0; i < program->n_functions; ++i) {
			const sil_function_v2_t *function = &program->functions[i];
			struct FunctionBundleV2 item = { 0 };
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
			item.loc = function->loc;
			item.nos = function->nos;
			item.pseudocode = sil_capnp_text(function->pseudocode);
			item.pseudocodeSource = sil_capnp_text(function->pseudocode_source);
			if (!sil_capnp_u64_list_new(seg, function->calls, function->n_calls, &item.calls)) {
				out.p.type = CAPN_NULL;
				return out;
			}
			item.name = sil_capnp_text(function->name);
			item.signature = sil_capnp_text(function->signature);
			item.callconv = sil_capnp_text(function->callconv);
			set_FunctionBundleV2(&item, functions, (int)i);
		}
		ProgramBundleV2_set_functions(out, functions);
	}

	return out;
}

bool sil_protocol_ping_v2_send(RzSocket *socket, const char *psk) {
	struct capn ctx;
	capn_init_malloc(&ctx);
	PingV2_ptr ping = new_PingV2(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(ping.p)) {
		capn_free(&ctx);
		return false;
	}

	struct RequestV2 request = { 0 };
	request.psk = sil_capnp_text(psk);
	request.version = RZ_SIL_VERSION_CAPNP;
	request.route = RouteV2_ping;
	request.which = RequestV2_ping;
	request.ping = ping;

	RequestV2_ptr reqp = new_RequestV2(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(reqp.p)) {
		capn_free(&ctx);
		return false;
	}
	write_RequestV2(&request, reqp);
	bool ok = capn_setp(capn_root(&ctx), 0, reqp.p) == 0;
	if (!ok) {
		capn_free(&ctx);
		return false;
	}
	ok = sil_protocol_capnp_send_ctx(socket, &ctx);
	capn_free(&ctx);
	return ok;
}

bool sil_protocol_resolve_program_v2_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program) {
	struct capn ctx;
	capn_init_malloc(&ctx);
	ProgramBundleV2_ptr prog = sil_capnp_program_new(capn_root(&ctx).seg, program);
	if (!sil_capnp_ptr_valid(prog.p)) {
		capn_free(&ctx);
		return false;
	}
	ResolveProgramV2_ptr resolve = new_ResolveProgramV2(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(resolve.p)) {
		capn_free(&ctx);
		return false;
	}
	ResolveProgramV2_set_program(resolve, prog);

	struct RequestV2 request = { 0 };
	request.psk = sil_capnp_text(psk);
	request.version = RZ_SIL_VERSION_CAPNP;
	request.route = RouteV2_resolveProgram;
	request.which = RequestV2_resolveProgram;
	request.resolveProgram = resolve;

	RequestV2_ptr reqp = new_RequestV2(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(reqp.p)) {
		capn_free(&ctx);
		return false;
	}
	write_RequestV2(&request, reqp);
	bool ok = capn_setp(capn_root(&ctx), 0, reqp.p) == 0;
	if (!ok) {
		capn_free(&ctx);
		return false;
	}
	ok = sil_protocol_capnp_send_ctx(socket, &ctx);
	capn_free(&ctx);
	return ok;
}

bool sil_protocol_share_program_v2_send(RzSocket *socket, const char *psk, const sil_program_bundle_t *program) {
	struct capn ctx;
	capn_init_malloc(&ctx);
	ProgramBundleV2_ptr prog = sil_capnp_program_new(capn_root(&ctx).seg, program);
	if (!sil_capnp_ptr_valid(prog.p)) {
		capn_free(&ctx);
		return false;
	}
	ShareProgramV2_ptr share = new_ShareProgramV2(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(share.p)) {
		capn_free(&ctx);
		return false;
	}
	ShareProgramV2_set_program(share, prog);

	struct RequestV2 request = { 0 };
	request.psk = sil_capnp_text(psk);
	request.version = RZ_SIL_VERSION_CAPNP;
	request.route = RouteV2_shareProgram;
	request.which = RequestV2_shareProgram;
	request.shareProgram = share;

	RequestV2_ptr reqp = new_RequestV2(capn_root(&ctx).seg);
	if (!sil_capnp_ptr_valid(reqp.p)) {
		capn_free(&ctx);
		return false;
	}
	write_RequestV2(&request, reqp);
	bool ok = capn_setp(capn_root(&ctx), 0, reqp.p) == 0;
	if (!ok) {
		capn_free(&ctx);
		return false;
	}
	ok = sil_protocol_capnp_send_ctx(socket, &ctx);
	capn_free(&ctx);
	return ok;
}

bool sil_protocol_response_v2_recv(RzSocket *socket, sil_v2_response_t *response) {
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

	ResponseV2_ptr root = { 0 };
	root.p = capn_getp(capn_root(&ctx), 0, 1);
	struct ResponseV2 message = { 0 };
	read_ResponseV2(&message, root);

	response->status = message.status;
	response->which = message.which;

	switch (message.which) {
	case ResponseV2_message: {
		struct MessageV2 text = { 0 };
		read_MessageV2(&text, message.message);
		response->text = sil_capnp_strdup(text.text);
		break;
	}
	case ResponseV2_serverInfo: {
		struct ServerInfoV2 info = { 0 };
		read_ServerInfoV2(&info, message.serverInfo);
		response->server_info.min_version = info.minVersion;
		response->server_info.max_version = info.maxVersion;
		response->server_info.keenhash_enabled = info.keenhashEnabled;
		response->server_info.decompiler_required = info.decompilerRequired;
		response->server_info.tls_required = info.tlsRequired;
		response->server_info.model_version = sil_capnp_strdup(info.modelVersion);
		response->server_info.index_version = sil_capnp_strdup(info.indexVersion);
		break;
	}
	case ResponseV2_resolveResult: {
		struct ResolveResultV2 result = { 0 };
		read_ResolveResultV2(&result, message.resolveResult);
		response->resolve_result.n_hints = capn_len(result.hints);
		response->resolve_result.hints = calloc(sizeof(sil_hint_v2_t), response->resolve_result.n_hints);
		for (size_t i = 0; i < response->resolve_result.n_hints; ++i) {
			struct HintV2 hint = { 0 };
			get_HintV2(&hint, result.hints, (int)i);
			response->resolve_result.hints[i].bits = hint.bits;
			response->resolve_result.hints[i].offset = hint.offset;
			response->resolve_result.hints[i].confidence = hint.confidence;
			response->resolve_result.hints[i].matched_binary_id = sil_capnp_strdup(hint.matchedBinaryId);
		}

		response->resolve_result.n_symbols = capn_len(result.symbols);
		response->resolve_result.symbols = calloc(sizeof(sil_symbol_match_v2_t), response->resolve_result.n_symbols);
		for (size_t i = 0; i < response->resolve_result.n_symbols; ++i) {
			struct SymbolMatchV2 match = { 0 };
			struct SymbolV2 symbol = { 0 };
			get_SymbolMatchV2(&match, result.symbols, (int)i);
			read_SymbolV2(&symbol, match.symbol);
			response->resolve_result.symbols[i].addr = match.addr;
			response->resolve_result.symbols[i].confidence = match.confidence;
			response->resolve_result.symbols[i].exact = match.exact;
			response->resolve_result.symbols[i].matched_binary_id = sil_capnp_strdup(match.matchedBinaryId);
			response->resolve_result.symbols[i].matched_by = sil_capnp_strdup(match.matchedBy);
			response->resolve_result.symbols[i].offset = match.offset;
			response->resolve_result.symbols[i].size = match.size;
			char *name = symbol.name.str ? sil_capnp_strdup(symbol.name) : NULL;
			char *signature = symbol.signature.str ? sil_capnp_strdup(symbol.signature) : NULL;
			char *callconv = symbol.callconv.str ? sil_capnp_strdup(symbol.callconv) : NULL;
			response->resolve_result.symbols[i].symbol = proto_symbol_new(name, signature, callconv, symbol.bits);
			free(name);
			free(signature);
			free(callconv);
		}

		capn_ptr candidate_ptr = result.candidateBinaryIds;
		capn_resolve(&candidate_ptr);
		response->resolve_result.n_candidate_binary_ids = candidate_ptr.len > 0 ? (size_t)candidate_ptr.len : 0;
		response->resolve_result.candidate_binary_ids = calloc(sizeof(char *), response->resolve_result.n_candidate_binary_ids);
		for (size_t i = 0; i < response->resolve_result.n_candidate_binary_ids; ++i) {
			response->resolve_result.candidate_binary_ids[i] = sil_capnp_strdup(capn_get_text(candidate_ptr, (int)i, sil_capnp_text("")));
		}
		response->resolve_result.model_version = sil_capnp_strdup(result.modelVersion);
		response->resolve_result.index_version = sil_capnp_strdup(result.indexVersion);
		break;
	}
	case ResponseV2_shareResult: {
		struct ShareResultV2 result = { 0 };
		read_ShareResultV2(&result, message.shareResult);
		response->share_result.binary_id = sil_capnp_strdup(result.binaryId);
		response->share_result.ingested_functions = result.ingestedFunctions;
		response->share_result.candidate_count = result.candidateCount;
		response->share_result.model_version = sil_capnp_strdup(result.modelVersion);
		response->share_result.index_version = sil_capnp_strdup(result.indexVersion);
		break;
	}
	default:
		break;
	}

	capn_free(&ctx);
	free(buffer);
	return true;
}
