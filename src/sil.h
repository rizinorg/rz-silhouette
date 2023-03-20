// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SIL_H
#define SIL_H

#include <rz_core.h>
#include <rz_cmd.h>
#include <rz_analysis.h>
#include <rz_socket.h>
#include <rz_th.h>

#include "sil_const.h"

typedef struct sil_opt_s {
	const char *psk;
	const char *address;
	const char *port;
	ut32 timeout;
	bool use_tls;
	bool show_msg;
	bool can_share;
	bool can_share_sections;
	bool can_share_symbols;
} sil_opt_t;

typedef struct sil_s sil_t;

typedef struct sil_stats_s {
	ut32 hints;
	ut32 symbols;
} sil_stats_t;

void sil_free(sil_t *sil);
sil_t *sil_new(sil_opt_t *opts);
bool sil_test_connection(sil_t *sil);
bool sil_share_binary(sil_t *sil, RzCore *core);
bool sil_resolve_functions(sil_t *sil, RzCore *core, sil_stats_t *stats);

#endif /* SIL_H */
