// SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
// SPDX-License-Identifier: LGPL-3.0-only

#include "sil_helpers.h"

char *sil_to_lower_dup(const char *original, const char *def_string) {
	const char *string = RZ_STR_ISEMPTY(original) ? def_string : original;
	if (RZ_STR_ISEMPTY(string)) {
		return NULL;
	}

	size_t length = strlen(string);
	char *normalized = RZ_NEWS0(char, length + 1);
	if (!normalized) {
		return NULL;
	}

	size_t j = 0;
	for (size_t i = 0; i < length; ++i) {
		if (!IS_ALPHANUM(string[i])) {
			continue;
		}
		normalized[j++] = tolower((ut8)string[i]);
	}

	if (j < 1) {
		free(normalized);
		return rz_str_dup(def_string);
	}

	return normalized;
}
