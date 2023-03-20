// SPDX-FileCopyrightText: 2023 RizinOrg <info@rizin.re>
// SPDX-FileCopyrightText: 2023 deroad <wargio@libero.it>
// SPDX-License-Identifier: LGPL-3.0-only

#ifndef SIL_CONST_H
#define SIL_CONST_H

#define RZ_IO_VA               "io.va"
#define RZ_ASM_ARCH            "asm.arch"
#define RZ_ANALYSIS_FCN_PREFIX "analysis.fcnprefix"

#define RZ_SIL_VERSION (1)

#define RZ_SIL_ENABLE         "silhouette.enable"
#define RZ_SIL_ENABLE_DEFAULT false
#define RZ_SIL_ENABLE_DESCR   "When set to true enables fetching data from the silhouette server."

#define RZ_SIL_HOST         "silhouette.host"
#define RZ_SIL_HOST_DEFAULT "127.0.0.1"
#define RZ_SIL_HOST_DESCR   "Hostname/ip address of the silhouette server."

#define RZ_SIL_PORT         "silhouette.port"
#define RZ_SIL_PORT_DEFAULT "9999"
#define RZ_SIL_PORT_DESCR   "Port number of the silhouette server."

#define RZ_SIL_TIMEOUT         "silhouette.timeout"
#define RZ_SIL_TIMEOUT_DEFAULT 5000
#define RZ_SIL_TIMEOUT_DESCR   "Connection timeout (in milliseconds)."

#define RZ_SIL_PATTERN_SIZE         "silhouette.pattern.size"
#define RZ_SIL_PATTERN_SIZE_DEFAULT 32
#define RZ_SIL_PATTERN_SIZE_DESCR   "Function pattern size."

#define RZ_SIL_TLS         "silhouette.tls"
#define RZ_SIL_TLS_DEFAULT false
#define RZ_SIL_TLS_DESCR   "Set it to true to use TLS (uses the system certificate store)."

#define RZ_SIL_PSK         "silhouette.psk"
#define RZ_SIL_PSK_DEFAULT ""
#define RZ_SIL_PSK_DESCR   "Pre-shared key to use to authenticate with the silhouette server."

#define RZ_SIL_SHARE         "silhouette.share"
#define RZ_SIL_SHARE_DEFAULT false
#define RZ_SIL_SHARE_DESCR   "Set it to true to share any binary with symbols to the server."

#define RZ_SIL_SHARE_SECTIONS         "silhouette.share.sections"
#define RZ_SIL_SHARE_SECTIONS_DEFAULT true
#define RZ_SIL_SHARE_SECTIONS_DESCR   "Set it to true to share the sections with the server."

#define RZ_SIL_SHARE_SYMBOLS         "silhouette.share.symbols"
#define RZ_SIL_SHARE_SYMBOLS_DEFAULT true
#define RZ_SIL_SHARE_SYMBOLS_DESCR   "Set it to true to share the symbols with the server."

#define RZ_SIL_SRV_TEXT         "silhouette.server.message"
#define RZ_SIL_SRV_TEXT_DEFAULT true
#define RZ_SIL_SRV_TEXT_DESCR   "When set to true shows any message received by the silhouette server."

#endif /* SIL_CONST_H */
