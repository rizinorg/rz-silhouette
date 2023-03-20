// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SIL_PROTOCOL_H
#define SIL_PROTOCOL_H

#include "sil.h"
#include "sil_helpers.h"

bool sil_protocol_ping_send(RzSocket *socket, const char *psk);
bool sil_protocol_binary_send(RzSocket *socket, const char *psk, Binary *binary);
bool sil_protocol_signature_send(RzSocket *socket, const char *psk, Signature *signature);
bool sil_protocol_share_bin_send(RzSocket *socket, const char *psk, ShareBin *sharebin);
bool sil_protocol_response_recv(RzSocket *socket, Status *status, void **message);

#endif /* SIL_PROTOCOL_H */
