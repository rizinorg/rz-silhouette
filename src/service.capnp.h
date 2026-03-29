#ifndef CAPN_A0F8F4CE58FDD4D6
#define CAPN_A0F8F4CE58FDD4D6
/* AUTO GENERATED - DO NOT EDIT */
#include <capnp_c.h>

#if CAPN_VERSION != 1
#error "version mismatch between capnp_c.h and generated code"
#endif

#ifndef capnp_nowarn
# ifdef __GNUC__
#  define capnp_nowarn __extension__
# else
#  define capnp_nowarn
# endif
#endif


#ifdef __cplusplus
extern "C" {
#endif

struct SilSectionHash;
struct SilHint;
struct SilSymbol;
struct SilFunctionBundle;
struct SilProgramBundle;
struct SilPing;
struct SilResolveProgram;
struct SilShareProgram;
struct SilRequest;
struct SilMessage;
struct SilServerInfo;
struct SilSymbolMatch;
struct SilResolveResult;
struct SilShareResult;
struct SilResponse;

typedef struct {capn_ptr p;} SilSectionHash_ptr;
typedef struct {capn_ptr p;} SilHint_ptr;
typedef struct {capn_ptr p;} SilSymbol_ptr;
typedef struct {capn_ptr p;} SilFunctionBundle_ptr;
typedef struct {capn_ptr p;} SilProgramBundle_ptr;
typedef struct {capn_ptr p;} SilPing_ptr;
typedef struct {capn_ptr p;} SilResolveProgram_ptr;
typedef struct {capn_ptr p;} SilShareProgram_ptr;
typedef struct {capn_ptr p;} SilRequest_ptr;
typedef struct {capn_ptr p;} SilMessage_ptr;
typedef struct {capn_ptr p;} SilServerInfo_ptr;
typedef struct {capn_ptr p;} SilSymbolMatch_ptr;
typedef struct {capn_ptr p;} SilResolveResult_ptr;
typedef struct {capn_ptr p;} SilShareResult_ptr;
typedef struct {capn_ptr p;} SilResponse_ptr;

typedef struct {capn_ptr p;} SilSectionHash_list;
typedef struct {capn_ptr p;} SilHint_list;
typedef struct {capn_ptr p;} SilSymbol_list;
typedef struct {capn_ptr p;} SilFunctionBundle_list;
typedef struct {capn_ptr p;} SilProgramBundle_list;
typedef struct {capn_ptr p;} SilPing_list;
typedef struct {capn_ptr p;} SilResolveProgram_list;
typedef struct {capn_ptr p;} SilShareProgram_list;
typedef struct {capn_ptr p;} SilRequest_list;
typedef struct {capn_ptr p;} SilMessage_list;
typedef struct {capn_ptr p;} SilServerInfo_list;
typedef struct {capn_ptr p;} SilSymbolMatch_list;
typedef struct {capn_ptr p;} SilResolveResult_list;
typedef struct {capn_ptr p;} SilShareResult_list;
typedef struct {capn_ptr p;} SilResponse_list;

enum SilCodec {
	SilCodec_capnp = 0
};

enum SilRoute {
	SilRoute_ping = 0,
	SilRoute_resolveProgram = 1,
	SilRoute_shareProgram = 2
};

enum SilStatus {
	SilStatus_internalError = 0,
	SilStatus_clientBadPreSharedKey = 1,
	SilStatus_clientNotAuthorized = 2,
	SilStatus_versionMismatch = 3,
	SilStatus_message = 4,
	SilStatus_serverInfo = 5,
	SilStatus_resolveResult = 6,
	SilStatus_shareResult = 7
};

struct SilSectionHash {
	uint32_t size;
	uint64_t paddr;
	capn_data digest;
	capn_text name;
};

static const size_t SilSectionHash_word_count = 2;

static const size_t SilSectionHash_pointer_count = 2;

static const size_t SilSectionHash_struct_bytes_count = 32;


uint32_t SilSectionHash_get_size(SilSectionHash_ptr p);

uint64_t SilSectionHash_get_paddr(SilSectionHash_ptr p);

capn_data SilSectionHash_get_digest(SilSectionHash_ptr p);

capn_text SilSectionHash_get_name(SilSectionHash_ptr p);

void SilSectionHash_set_size(SilSectionHash_ptr p, uint32_t size);

void SilSectionHash_set_paddr(SilSectionHash_ptr p, uint64_t paddr);

void SilSectionHash_set_digest(SilSectionHash_ptr p, capn_data digest);

void SilSectionHash_set_name(SilSectionHash_ptr p, capn_text name);

struct SilHint {
	uint32_t bits;
	uint64_t offset;
};

static const size_t SilHint_word_count = 2;

static const size_t SilHint_pointer_count = 0;

static const size_t SilHint_struct_bytes_count = 16;


uint32_t SilHint_get_bits(SilHint_ptr p);

uint64_t SilHint_get_offset(SilHint_ptr p);

void SilHint_set_bits(SilHint_ptr p, uint32_t bits);

void SilHint_set_offset(SilHint_ptr p, uint64_t offset);

struct SilSymbol {
	capn_text name;
	capn_text signature;
	capn_text callconv;
	uint32_t bits;
};

static const size_t SilSymbol_word_count = 1;

static const size_t SilSymbol_pointer_count = 3;

static const size_t SilSymbol_struct_bytes_count = 32;


capn_text SilSymbol_get_name(SilSymbol_ptr p);

capn_text SilSymbol_get_signature(SilSymbol_ptr p);

capn_text SilSymbol_get_callconv(SilSymbol_ptr p);

uint32_t SilSymbol_get_bits(SilSymbol_ptr p);

void SilSymbol_set_name(SilSymbol_ptr p, capn_text name);

void SilSymbol_set_signature(SilSymbol_ptr p, capn_text signature);

void SilSymbol_set_callconv(SilSymbol_ptr p, capn_text callconv);

void SilSymbol_set_bits(SilSymbol_ptr p, uint32_t bits);

struct SilFunctionBundle {
	uint64_t addr;
	uint32_t size;
	uint32_t bits;
	capn_text arch;
	uint32_t length;
	capn_data digest;
	capn_text sectionName;
	uint64_t sectionPaddr;
	capn_text name;
	capn_text signature;
	capn_text callconv;
	uint64_t sectionOffset;
};

static const size_t SilFunctionBundle_word_count = 5;

static const size_t SilFunctionBundle_pointer_count = 6;

static const size_t SilFunctionBundle_struct_bytes_count = 88;


uint64_t SilFunctionBundle_get_addr(SilFunctionBundle_ptr p);

uint32_t SilFunctionBundle_get_size(SilFunctionBundle_ptr p);

uint32_t SilFunctionBundle_get_bits(SilFunctionBundle_ptr p);

capn_text SilFunctionBundle_get_arch(SilFunctionBundle_ptr p);

uint32_t SilFunctionBundle_get_length(SilFunctionBundle_ptr p);

capn_data SilFunctionBundle_get_digest(SilFunctionBundle_ptr p);

capn_text SilFunctionBundle_get_sectionName(SilFunctionBundle_ptr p);

uint64_t SilFunctionBundle_get_sectionPaddr(SilFunctionBundle_ptr p);

capn_text SilFunctionBundle_get_name(SilFunctionBundle_ptr p);

capn_text SilFunctionBundle_get_signature(SilFunctionBundle_ptr p);

capn_text SilFunctionBundle_get_callconv(SilFunctionBundle_ptr p);

uint64_t SilFunctionBundle_get_sectionOffset(SilFunctionBundle_ptr p);

void SilFunctionBundle_set_addr(SilFunctionBundle_ptr p, uint64_t addr);

void SilFunctionBundle_set_size(SilFunctionBundle_ptr p, uint32_t size);

void SilFunctionBundle_set_bits(SilFunctionBundle_ptr p, uint32_t bits);

void SilFunctionBundle_set_arch(SilFunctionBundle_ptr p, capn_text arch);

void SilFunctionBundle_set_length(SilFunctionBundle_ptr p, uint32_t length);

void SilFunctionBundle_set_digest(SilFunctionBundle_ptr p, capn_data digest);

void SilFunctionBundle_set_sectionName(SilFunctionBundle_ptr p, capn_text sectionName);

void SilFunctionBundle_set_sectionPaddr(SilFunctionBundle_ptr p, uint64_t sectionPaddr);

void SilFunctionBundle_set_name(SilFunctionBundle_ptr p, capn_text name);

void SilFunctionBundle_set_signature(SilFunctionBundle_ptr p, capn_text signature);

void SilFunctionBundle_set_callconv(SilFunctionBundle_ptr p, capn_text callconv);

void SilFunctionBundle_set_sectionOffset(SilFunctionBundle_ptr p, uint64_t sectionOffset);

struct SilProgramBundle {
	capn_text binaryType;
	capn_text os;
	capn_text arch;
	uint32_t bits;
	capn_text binaryId;
	SilSectionHash_list sections;
	SilFunctionBundle_list functions;
};

static const size_t SilProgramBundle_word_count = 1;

static const size_t SilProgramBundle_pointer_count = 6;

static const size_t SilProgramBundle_struct_bytes_count = 56;


capn_text SilProgramBundle_get_binaryType(SilProgramBundle_ptr p);

capn_text SilProgramBundle_get_os(SilProgramBundle_ptr p);

capn_text SilProgramBundle_get_arch(SilProgramBundle_ptr p);

uint32_t SilProgramBundle_get_bits(SilProgramBundle_ptr p);

capn_text SilProgramBundle_get_binaryId(SilProgramBundle_ptr p);

SilSectionHash_list SilProgramBundle_get_sections(SilProgramBundle_ptr p);

SilFunctionBundle_list SilProgramBundle_get_functions(SilProgramBundle_ptr p);

void SilProgramBundle_set_binaryType(SilProgramBundle_ptr p, capn_text binaryType);

void SilProgramBundle_set_os(SilProgramBundle_ptr p, capn_text os);

void SilProgramBundle_set_arch(SilProgramBundle_ptr p, capn_text arch);

void SilProgramBundle_set_bits(SilProgramBundle_ptr p, uint32_t bits);

void SilProgramBundle_set_binaryId(SilProgramBundle_ptr p, capn_text binaryId);

void SilProgramBundle_set_sections(SilProgramBundle_ptr p, SilSectionHash_list sections);

void SilProgramBundle_set_functions(SilProgramBundle_ptr p, SilFunctionBundle_list functions);

struct SilPing {
	unsigned reserved : 1;
};

static const size_t SilPing_word_count = 1;

static const size_t SilPing_pointer_count = 0;

static const size_t SilPing_struct_bytes_count = 8;


unsigned SilPing_get_reserved(SilPing_ptr p);

void SilPing_set_reserved(SilPing_ptr p, unsigned reserved);

struct SilResolveProgram {
	SilProgramBundle_ptr program;
};

static const size_t SilResolveProgram_word_count = 0;

static const size_t SilResolveProgram_pointer_count = 1;

static const size_t SilResolveProgram_struct_bytes_count = 8;


SilProgramBundle_ptr SilResolveProgram_get_program(SilResolveProgram_ptr p);

void SilResolveProgram_set_program(SilResolveProgram_ptr p, SilProgramBundle_ptr program);

struct SilShareProgram {
	SilProgramBundle_ptr program;
};

static const size_t SilShareProgram_word_count = 0;

static const size_t SilShareProgram_pointer_count = 1;

static const size_t SilShareProgram_struct_bytes_count = 8;


SilProgramBundle_ptr SilShareProgram_get_program(SilShareProgram_ptr p);

void SilShareProgram_set_program(SilShareProgram_ptr p, SilProgramBundle_ptr program);
enum SilRequest_which {
	SilRequest_ping = 0,
	SilRequest_resolveProgram = 1,
	SilRequest_shareProgram = 2
};

struct SilRequest {
	capn_text psk;
	uint32_t version;
	enum SilRoute route;
	enum SilRequest_which which;
	capnp_nowarn union {
		SilPing_ptr ping;
		SilResolveProgram_ptr resolveProgram;
		SilShareProgram_ptr shareProgram;
	};
};

static const size_t SilRequest_word_count = 1;

static const size_t SilRequest_pointer_count = 2;

static const size_t SilRequest_struct_bytes_count = 24;


capn_text SilRequest_get_psk(SilRequest_ptr p);

uint32_t SilRequest_get_version(SilRequest_ptr p);

enum SilRoute SilRequest_get_route(SilRequest_ptr p);

void SilRequest_set_psk(SilRequest_ptr p, capn_text psk);

void SilRequest_set_version(SilRequest_ptr p, uint32_t version);

void SilRequest_set_route(SilRequest_ptr p, enum SilRoute route);

struct SilMessage {
	capn_text text;
};

static const size_t SilMessage_word_count = 0;

static const size_t SilMessage_pointer_count = 1;

static const size_t SilMessage_struct_bytes_count = 8;


capn_text SilMessage_get_text(SilMessage_ptr p);

void SilMessage_set_text(SilMessage_ptr p, capn_text text);

struct SilServerInfo {
	capn_list16 supportedCodecs;
	uint32_t version;
	unsigned tlsRequired : 1;
};

static const size_t SilServerInfo_word_count = 1;

static const size_t SilServerInfo_pointer_count = 1;

static const size_t SilServerInfo_struct_bytes_count = 16;


capn_list16 SilServerInfo_get_supportedCodecs(SilServerInfo_ptr p);

uint32_t SilServerInfo_get_version(SilServerInfo_ptr p);

unsigned SilServerInfo_get_tlsRequired(SilServerInfo_ptr p);

void SilServerInfo_set_supportedCodecs(SilServerInfo_ptr p, capn_list16 supportedCodecs);

void SilServerInfo_set_version(SilServerInfo_ptr p, uint32_t version);

void SilServerInfo_set_tlsRequired(SilServerInfo_ptr p, unsigned tlsRequired);

struct SilSymbolMatch {
	uint64_t addr;
	SilSymbol_ptr symbol;
	unsigned exact : 1;
	capn_text matchedBinaryId;
	capn_text matchedBy;
	uint64_t offset;
	uint32_t size;
};

static const size_t SilSymbolMatch_word_count = 3;

static const size_t SilSymbolMatch_pointer_count = 3;

static const size_t SilSymbolMatch_struct_bytes_count = 48;


uint64_t SilSymbolMatch_get_addr(SilSymbolMatch_ptr p);

SilSymbol_ptr SilSymbolMatch_get_symbol(SilSymbolMatch_ptr p);

unsigned SilSymbolMatch_get_exact(SilSymbolMatch_ptr p);

capn_text SilSymbolMatch_get_matchedBinaryId(SilSymbolMatch_ptr p);

capn_text SilSymbolMatch_get_matchedBy(SilSymbolMatch_ptr p);

uint64_t SilSymbolMatch_get_offset(SilSymbolMatch_ptr p);

uint32_t SilSymbolMatch_get_size(SilSymbolMatch_ptr p);

void SilSymbolMatch_set_addr(SilSymbolMatch_ptr p, uint64_t addr);

void SilSymbolMatch_set_symbol(SilSymbolMatch_ptr p, SilSymbol_ptr symbol);

void SilSymbolMatch_set_exact(SilSymbolMatch_ptr p, unsigned exact);

void SilSymbolMatch_set_matchedBinaryId(SilSymbolMatch_ptr p, capn_text matchedBinaryId);

void SilSymbolMatch_set_matchedBy(SilSymbolMatch_ptr p, capn_text matchedBy);

void SilSymbolMatch_set_offset(SilSymbolMatch_ptr p, uint64_t offset);

void SilSymbolMatch_set_size(SilSymbolMatch_ptr p, uint32_t size);

struct SilResolveResult {
	SilHint_list hints;
	SilSymbolMatch_list symbols;
};

static const size_t SilResolveResult_word_count = 0;

static const size_t SilResolveResult_pointer_count = 2;

static const size_t SilResolveResult_struct_bytes_count = 16;


SilHint_list SilResolveResult_get_hints(SilResolveResult_ptr p);

SilSymbolMatch_list SilResolveResult_get_symbols(SilResolveResult_ptr p);

void SilResolveResult_set_hints(SilResolveResult_ptr p, SilHint_list hints);

void SilResolveResult_set_symbols(SilResolveResult_ptr p, SilSymbolMatch_list symbols);

struct SilShareResult {
	capn_text binaryId;
};

static const size_t SilShareResult_word_count = 0;

static const size_t SilShareResult_pointer_count = 1;

static const size_t SilShareResult_struct_bytes_count = 8;


capn_text SilShareResult_get_binaryId(SilShareResult_ptr p);

void SilShareResult_set_binaryId(SilShareResult_ptr p, capn_text binaryId);
enum SilResponse_which {
	SilResponse_message = 0,
	SilResponse_serverInfo = 1,
	SilResponse_resolveResult = 2,
	SilResponse_shareResult = 3
};

struct SilResponse {
	enum SilStatus status;
	enum SilResponse_which which;
	capnp_nowarn union {
		SilMessage_ptr message;
		SilServerInfo_ptr serverInfo;
		SilResolveResult_ptr resolveResult;
		SilShareResult_ptr shareResult;
	};
};

static const size_t SilResponse_word_count = 1;

static const size_t SilResponse_pointer_count = 1;

static const size_t SilResponse_struct_bytes_count = 16;


enum SilStatus SilResponse_get_status(SilResponse_ptr p);

void SilResponse_set_status(SilResponse_ptr p, enum SilStatus status);

SilSectionHash_ptr new_SilSectionHash(struct capn_segment*);
SilHint_ptr new_SilHint(struct capn_segment*);
SilSymbol_ptr new_SilSymbol(struct capn_segment*);
SilFunctionBundle_ptr new_SilFunctionBundle(struct capn_segment*);
SilProgramBundle_ptr new_SilProgramBundle(struct capn_segment*);
SilPing_ptr new_SilPing(struct capn_segment*);
SilResolveProgram_ptr new_SilResolveProgram(struct capn_segment*);
SilShareProgram_ptr new_SilShareProgram(struct capn_segment*);
SilRequest_ptr new_SilRequest(struct capn_segment*);
SilMessage_ptr new_SilMessage(struct capn_segment*);
SilServerInfo_ptr new_SilServerInfo(struct capn_segment*);
SilSymbolMatch_ptr new_SilSymbolMatch(struct capn_segment*);
SilResolveResult_ptr new_SilResolveResult(struct capn_segment*);
SilShareResult_ptr new_SilShareResult(struct capn_segment*);
SilResponse_ptr new_SilResponse(struct capn_segment*);

SilSectionHash_list new_SilSectionHash_list(struct capn_segment*, int len);
SilHint_list new_SilHint_list(struct capn_segment*, int len);
SilSymbol_list new_SilSymbol_list(struct capn_segment*, int len);
SilFunctionBundle_list new_SilFunctionBundle_list(struct capn_segment*, int len);
SilProgramBundle_list new_SilProgramBundle_list(struct capn_segment*, int len);
SilPing_list new_SilPing_list(struct capn_segment*, int len);
SilResolveProgram_list new_SilResolveProgram_list(struct capn_segment*, int len);
SilShareProgram_list new_SilShareProgram_list(struct capn_segment*, int len);
SilRequest_list new_SilRequest_list(struct capn_segment*, int len);
SilMessage_list new_SilMessage_list(struct capn_segment*, int len);
SilServerInfo_list new_SilServerInfo_list(struct capn_segment*, int len);
SilSymbolMatch_list new_SilSymbolMatch_list(struct capn_segment*, int len);
SilResolveResult_list new_SilResolveResult_list(struct capn_segment*, int len);
SilShareResult_list new_SilShareResult_list(struct capn_segment*, int len);
SilResponse_list new_SilResponse_list(struct capn_segment*, int len);

void read_SilSectionHash(struct SilSectionHash*, SilSectionHash_ptr);
void read_SilHint(struct SilHint*, SilHint_ptr);
void read_SilSymbol(struct SilSymbol*, SilSymbol_ptr);
void read_SilFunctionBundle(struct SilFunctionBundle*, SilFunctionBundle_ptr);
void read_SilProgramBundle(struct SilProgramBundle*, SilProgramBundle_ptr);
void read_SilPing(struct SilPing*, SilPing_ptr);
void read_SilResolveProgram(struct SilResolveProgram*, SilResolveProgram_ptr);
void read_SilShareProgram(struct SilShareProgram*, SilShareProgram_ptr);
void read_SilRequest(struct SilRequest*, SilRequest_ptr);
void read_SilMessage(struct SilMessage*, SilMessage_ptr);
void read_SilServerInfo(struct SilServerInfo*, SilServerInfo_ptr);
void read_SilSymbolMatch(struct SilSymbolMatch*, SilSymbolMatch_ptr);
void read_SilResolveResult(struct SilResolveResult*, SilResolveResult_ptr);
void read_SilShareResult(struct SilShareResult*, SilShareResult_ptr);
void read_SilResponse(struct SilResponse*, SilResponse_ptr);

void write_SilSectionHash(const struct SilSectionHash*, SilSectionHash_ptr);
void write_SilHint(const struct SilHint*, SilHint_ptr);
void write_SilSymbol(const struct SilSymbol*, SilSymbol_ptr);
void write_SilFunctionBundle(const struct SilFunctionBundle*, SilFunctionBundle_ptr);
void write_SilProgramBundle(const struct SilProgramBundle*, SilProgramBundle_ptr);
void write_SilPing(const struct SilPing*, SilPing_ptr);
void write_SilResolveProgram(const struct SilResolveProgram*, SilResolveProgram_ptr);
void write_SilShareProgram(const struct SilShareProgram*, SilShareProgram_ptr);
void write_SilRequest(const struct SilRequest*, SilRequest_ptr);
void write_SilMessage(const struct SilMessage*, SilMessage_ptr);
void write_SilServerInfo(const struct SilServerInfo*, SilServerInfo_ptr);
void write_SilSymbolMatch(const struct SilSymbolMatch*, SilSymbolMatch_ptr);
void write_SilResolveResult(const struct SilResolveResult*, SilResolveResult_ptr);
void write_SilShareResult(const struct SilShareResult*, SilShareResult_ptr);
void write_SilResponse(const struct SilResponse*, SilResponse_ptr);

void get_SilSectionHash(struct SilSectionHash*, SilSectionHash_list, int i);
void get_SilHint(struct SilHint*, SilHint_list, int i);
void get_SilSymbol(struct SilSymbol*, SilSymbol_list, int i);
void get_SilFunctionBundle(struct SilFunctionBundle*, SilFunctionBundle_list, int i);
void get_SilProgramBundle(struct SilProgramBundle*, SilProgramBundle_list, int i);
void get_SilPing(struct SilPing*, SilPing_list, int i);
void get_SilResolveProgram(struct SilResolveProgram*, SilResolveProgram_list, int i);
void get_SilShareProgram(struct SilShareProgram*, SilShareProgram_list, int i);
void get_SilRequest(struct SilRequest*, SilRequest_list, int i);
void get_SilMessage(struct SilMessage*, SilMessage_list, int i);
void get_SilServerInfo(struct SilServerInfo*, SilServerInfo_list, int i);
void get_SilSymbolMatch(struct SilSymbolMatch*, SilSymbolMatch_list, int i);
void get_SilResolveResult(struct SilResolveResult*, SilResolveResult_list, int i);
void get_SilShareResult(struct SilShareResult*, SilShareResult_list, int i);
void get_SilResponse(struct SilResponse*, SilResponse_list, int i);

void set_SilSectionHash(const struct SilSectionHash*, SilSectionHash_list, int i);
void set_SilHint(const struct SilHint*, SilHint_list, int i);
void set_SilSymbol(const struct SilSymbol*, SilSymbol_list, int i);
void set_SilFunctionBundle(const struct SilFunctionBundle*, SilFunctionBundle_list, int i);
void set_SilProgramBundle(const struct SilProgramBundle*, SilProgramBundle_list, int i);
void set_SilPing(const struct SilPing*, SilPing_list, int i);
void set_SilResolveProgram(const struct SilResolveProgram*, SilResolveProgram_list, int i);
void set_SilShareProgram(const struct SilShareProgram*, SilShareProgram_list, int i);
void set_SilRequest(const struct SilRequest*, SilRequest_list, int i);
void set_SilMessage(const struct SilMessage*, SilMessage_list, int i);
void set_SilServerInfo(const struct SilServerInfo*, SilServerInfo_list, int i);
void set_SilSymbolMatch(const struct SilSymbolMatch*, SilSymbolMatch_list, int i);
void set_SilResolveResult(const struct SilResolveResult*, SilResolveResult_list, int i);
void set_SilShareResult(const struct SilShareResult*, SilShareResult_list, int i);
void set_SilResponse(const struct SilResponse*, SilResponse_list, int i);

#ifdef __cplusplus
}
#endif
#endif
