// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

/** \file sil_protocol.c
 * Silhouette protocol functions.
 */

#include "sil_protocol.h"

#define SIL_HEADER_SIZE (sizeof(ut32))

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

	int written = rz_socket_write(socket, buffer, size + SIL_HEADER_SIZE);
	rz_socket_flush(socket);
	free(buffer);

	if (written > 0) {
		return true;
	}

	RZ_LOG_ERROR("silhouette: failed to send bytes to the server\n");
	return false;
}

bool sil_protocol_response_recv(RzSocket *socket, Status *status, void **message) {
	ut8 header[SIL_HEADER_SIZE] = { 0 };
	if (rz_socket_read(socket, header, sizeof(header)) != sizeof(header)) {
		RZ_LOG_ERROR("silhouette: failed to read response packed size\n");
		return false;
	}

	ut32 size = rz_read_be32(header);
	ut8 *buffer = size > 0 ? malloc(size) : NULL;
	if (!buffer) {
		RZ_LOG_ERROR("silhouette: failed to allocate response packed bytes\n");
		return false;
	}

	if (!rz_socket_read(socket, buffer, size)) {
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
		RZ_LOG_ERROR("silhouette: failed to allocate share bin packed bytes\n");
		return false;
	}

	Request *req = proto_request_binary_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate request share bin\n");
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
		RZ_LOG_ERROR("silhouette: failed to allocate share bin packed bytes\n");
		return false;
	}

	Request *req = proto_request_signature_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate request share bin\n");
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
		RZ_LOG_ERROR("silhouette: failed to allocate share bin packed bytes\n");
		return false;
	}

	Request *req = proto_request_share_bin_new(psk);
	if (!req) {
		RZ_LOG_ERROR("silhouette: failed to allocate request share bin\n");
		free(message);
		return false;
	}
	share_bin__pack(sharebin, message);

	req->message.data = message;
	req->message.len = size;
	return sil_protocol_request_send(socket, req);
}
