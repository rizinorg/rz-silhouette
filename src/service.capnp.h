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

struct SectionHashV2;
struct HintV2;
struct SymbolV2;
struct FunctionBundleV2;
struct ProgramBundleV2;
struct PingV2;
struct ResolveProgramV2;
struct ShareProgramV2;
struct RequestV2;
struct MessageV2;
struct ServerInfoV2;
struct SymbolMatchV2;
struct ResolveResultV2;
struct ShareResultV2;
struct ResponseV2;

typedef struct {capn_ptr p;} SectionHashV2_ptr;
typedef struct {capn_ptr p;} HintV2_ptr;
typedef struct {capn_ptr p;} SymbolV2_ptr;
typedef struct {capn_ptr p;} FunctionBundleV2_ptr;
typedef struct {capn_ptr p;} ProgramBundleV2_ptr;
typedef struct {capn_ptr p;} PingV2_ptr;
typedef struct {capn_ptr p;} ResolveProgramV2_ptr;
typedef struct {capn_ptr p;} ShareProgramV2_ptr;
typedef struct {capn_ptr p;} RequestV2_ptr;
typedef struct {capn_ptr p;} MessageV2_ptr;
typedef struct {capn_ptr p;} ServerInfoV2_ptr;
typedef struct {capn_ptr p;} SymbolMatchV2_ptr;
typedef struct {capn_ptr p;} ResolveResultV2_ptr;
typedef struct {capn_ptr p;} ShareResultV2_ptr;
typedef struct {capn_ptr p;} ResponseV2_ptr;

typedef struct {capn_ptr p;} SectionHashV2_list;
typedef struct {capn_ptr p;} HintV2_list;
typedef struct {capn_ptr p;} SymbolV2_list;
typedef struct {capn_ptr p;} FunctionBundleV2_list;
typedef struct {capn_ptr p;} ProgramBundleV2_list;
typedef struct {capn_ptr p;} PingV2_list;
typedef struct {capn_ptr p;} ResolveProgramV2_list;
typedef struct {capn_ptr p;} ShareProgramV2_list;
typedef struct {capn_ptr p;} RequestV2_list;
typedef struct {capn_ptr p;} MessageV2_list;
typedef struct {capn_ptr p;} ServerInfoV2_list;
typedef struct {capn_ptr p;} SymbolMatchV2_list;
typedef struct {capn_ptr p;} ResolveResultV2_list;
typedef struct {capn_ptr p;} ShareResultV2_list;
typedef struct {capn_ptr p;} ResponseV2_list;

enum CodecV2 {
	CodecV2_protobuf = 0,
	CodecV2_capnp = 1
};

enum RouteV2 {
	RouteV2_ping = 0,
	RouteV2_resolveProgram = 1,
	RouteV2_shareProgram = 2
};

enum StatusV2 {
	StatusV2_internalError = 0,
	StatusV2_clientBadPreSharedKey = 1,
	StatusV2_clientNotAuthorized = 2,
	StatusV2_versionMismatch = 3,
	StatusV2_shareWasSuccessful = 4,
	StatusV2_message = 5,
	StatusV2_serverInfo = 6,
	StatusV2_resolveResult = 7,
	StatusV2_shareResult = 8
};

struct SectionHashV2 {
	uint32_t size;
	uint64_t paddr;
	capn_data digest;
	capn_text name;
};

static const size_t SectionHashV2_word_count = 2;

static const size_t SectionHashV2_pointer_count = 2;

static const size_t SectionHashV2_struct_bytes_count = 32;


uint32_t SectionHashV2_get_size(SectionHashV2_ptr p);

uint64_t SectionHashV2_get_paddr(SectionHashV2_ptr p);

capn_data SectionHashV2_get_digest(SectionHashV2_ptr p);

capn_text SectionHashV2_get_name(SectionHashV2_ptr p);

void SectionHashV2_set_size(SectionHashV2_ptr p, uint32_t size);

void SectionHashV2_set_paddr(SectionHashV2_ptr p, uint64_t paddr);

void SectionHashV2_set_digest(SectionHashV2_ptr p, capn_data digest);

void SectionHashV2_set_name(SectionHashV2_ptr p, capn_text name);

struct HintV2 {
	uint32_t bits;
	uint64_t offset;
	float confidence;
	capn_text matchedBinaryId;
};

static const size_t HintV2_word_count = 2;

static const size_t HintV2_pointer_count = 1;

static const size_t HintV2_struct_bytes_count = 24;


uint32_t HintV2_get_bits(HintV2_ptr p);

uint64_t HintV2_get_offset(HintV2_ptr p);

float HintV2_get_confidence(HintV2_ptr p);

capn_text HintV2_get_matchedBinaryId(HintV2_ptr p);

void HintV2_set_bits(HintV2_ptr p, uint32_t bits);

void HintV2_set_offset(HintV2_ptr p, uint64_t offset);

void HintV2_set_confidence(HintV2_ptr p, float confidence);

void HintV2_set_matchedBinaryId(HintV2_ptr p, capn_text matchedBinaryId);

struct SymbolV2 {
	capn_text name;
	capn_text signature;
	capn_text callconv;
	uint32_t bits;
};

static const size_t SymbolV2_word_count = 1;

static const size_t SymbolV2_pointer_count = 3;

static const size_t SymbolV2_struct_bytes_count = 32;


capn_text SymbolV2_get_name(SymbolV2_ptr p);

capn_text SymbolV2_get_signature(SymbolV2_ptr p);

capn_text SymbolV2_get_callconv(SymbolV2_ptr p);

uint32_t SymbolV2_get_bits(SymbolV2_ptr p);

void SymbolV2_set_name(SymbolV2_ptr p, capn_text name);

void SymbolV2_set_signature(SymbolV2_ptr p, capn_text signature);

void SymbolV2_set_callconv(SymbolV2_ptr p, capn_text callconv);

void SymbolV2_set_bits(SymbolV2_ptr p, uint32_t bits);

struct FunctionBundleV2 {
	uint64_t addr;
	uint32_t size;
	uint32_t bits;
	capn_text arch;
	uint32_t length;
	capn_data digest;
	capn_text sectionName;
	uint64_t sectionPaddr;
	uint32_t loc;
	uint32_t nos;
	capn_text pseudocode;
	capn_list64 calls;
	capn_text name;
	capn_text signature;
	capn_text callconv;
	capn_text pseudocodeSource;
	uint64_t sectionOffset;
};

static const size_t FunctionBundleV2_word_count = 6;

static const size_t FunctionBundleV2_pointer_count = 9;

static const size_t FunctionBundleV2_struct_bytes_count = 120;


uint64_t FunctionBundleV2_get_addr(FunctionBundleV2_ptr p);

uint32_t FunctionBundleV2_get_size(FunctionBundleV2_ptr p);

uint32_t FunctionBundleV2_get_bits(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_arch(FunctionBundleV2_ptr p);

uint32_t FunctionBundleV2_get_length(FunctionBundleV2_ptr p);

capn_data FunctionBundleV2_get_digest(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_sectionName(FunctionBundleV2_ptr p);

uint64_t FunctionBundleV2_get_sectionPaddr(FunctionBundleV2_ptr p);

uint32_t FunctionBundleV2_get_loc(FunctionBundleV2_ptr p);

uint32_t FunctionBundleV2_get_nos(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_pseudocode(FunctionBundleV2_ptr p);

capn_list64 FunctionBundleV2_get_calls(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_name(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_signature(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_callconv(FunctionBundleV2_ptr p);

capn_text FunctionBundleV2_get_pseudocodeSource(FunctionBundleV2_ptr p);

uint64_t FunctionBundleV2_get_sectionOffset(FunctionBundleV2_ptr p);

void FunctionBundleV2_set_addr(FunctionBundleV2_ptr p, uint64_t addr);

void FunctionBundleV2_set_size(FunctionBundleV2_ptr p, uint32_t size);

void FunctionBundleV2_set_bits(FunctionBundleV2_ptr p, uint32_t bits);

void FunctionBundleV2_set_arch(FunctionBundleV2_ptr p, capn_text arch);

void FunctionBundleV2_set_length(FunctionBundleV2_ptr p, uint32_t length);

void FunctionBundleV2_set_digest(FunctionBundleV2_ptr p, capn_data digest);

void FunctionBundleV2_set_sectionName(FunctionBundleV2_ptr p, capn_text sectionName);

void FunctionBundleV2_set_sectionPaddr(FunctionBundleV2_ptr p, uint64_t sectionPaddr);

void FunctionBundleV2_set_loc(FunctionBundleV2_ptr p, uint32_t loc);

void FunctionBundleV2_set_nos(FunctionBundleV2_ptr p, uint32_t nos);

void FunctionBundleV2_set_pseudocode(FunctionBundleV2_ptr p, capn_text pseudocode);

void FunctionBundleV2_set_calls(FunctionBundleV2_ptr p, capn_list64 calls);

void FunctionBundleV2_set_name(FunctionBundleV2_ptr p, capn_text name);

void FunctionBundleV2_set_signature(FunctionBundleV2_ptr p, capn_text signature);

void FunctionBundleV2_set_callconv(FunctionBundleV2_ptr p, capn_text callconv);

void FunctionBundleV2_set_pseudocodeSource(FunctionBundleV2_ptr p, capn_text pseudocodeSource);

void FunctionBundleV2_set_sectionOffset(FunctionBundleV2_ptr p, uint64_t sectionOffset);

struct ProgramBundleV2 {
	capn_text binaryType;
	capn_text os;
	capn_text arch;
	uint32_t bits;
	capn_text binaryId;
	SectionHashV2_list sections;
	FunctionBundleV2_list functions;
	uint32_t topk;
};

static const size_t ProgramBundleV2_word_count = 1;

static const size_t ProgramBundleV2_pointer_count = 6;

static const size_t ProgramBundleV2_struct_bytes_count = 56;


capn_text ProgramBundleV2_get_binaryType(ProgramBundleV2_ptr p);

capn_text ProgramBundleV2_get_os(ProgramBundleV2_ptr p);

capn_text ProgramBundleV2_get_arch(ProgramBundleV2_ptr p);

uint32_t ProgramBundleV2_get_bits(ProgramBundleV2_ptr p);

capn_text ProgramBundleV2_get_binaryId(ProgramBundleV2_ptr p);

SectionHashV2_list ProgramBundleV2_get_sections(ProgramBundleV2_ptr p);

FunctionBundleV2_list ProgramBundleV2_get_functions(ProgramBundleV2_ptr p);

uint32_t ProgramBundleV2_get_topk(ProgramBundleV2_ptr p);

void ProgramBundleV2_set_binaryType(ProgramBundleV2_ptr p, capn_text binaryType);

void ProgramBundleV2_set_os(ProgramBundleV2_ptr p, capn_text os);

void ProgramBundleV2_set_arch(ProgramBundleV2_ptr p, capn_text arch);

void ProgramBundleV2_set_bits(ProgramBundleV2_ptr p, uint32_t bits);

void ProgramBundleV2_set_binaryId(ProgramBundleV2_ptr p, capn_text binaryId);

void ProgramBundleV2_set_sections(ProgramBundleV2_ptr p, SectionHashV2_list sections);

void ProgramBundleV2_set_functions(ProgramBundleV2_ptr p, FunctionBundleV2_list functions);

void ProgramBundleV2_set_topk(ProgramBundleV2_ptr p, uint32_t topk);

struct PingV2 {
	unsigned reserved : 1;
};

static const size_t PingV2_word_count = 1;

static const size_t PingV2_pointer_count = 0;

static const size_t PingV2_struct_bytes_count = 8;


unsigned PingV2_get_reserved(PingV2_ptr p);

void PingV2_set_reserved(PingV2_ptr p, unsigned reserved);

struct ResolveProgramV2 {
	ProgramBundleV2_ptr program;
};

static const size_t ResolveProgramV2_word_count = 0;

static const size_t ResolveProgramV2_pointer_count = 1;

static const size_t ResolveProgramV2_struct_bytes_count = 8;


ProgramBundleV2_ptr ResolveProgramV2_get_program(ResolveProgramV2_ptr p);

void ResolveProgramV2_set_program(ResolveProgramV2_ptr p, ProgramBundleV2_ptr program);

struct ShareProgramV2 {
	ProgramBundleV2_ptr program;
};

static const size_t ShareProgramV2_word_count = 0;

static const size_t ShareProgramV2_pointer_count = 1;

static const size_t ShareProgramV2_struct_bytes_count = 8;


ProgramBundleV2_ptr ShareProgramV2_get_program(ShareProgramV2_ptr p);

void ShareProgramV2_set_program(ShareProgramV2_ptr p, ProgramBundleV2_ptr program);
enum RequestV2_which {
	RequestV2_ping = 0,
	RequestV2_resolveProgram = 1,
	RequestV2_shareProgram = 2
};

struct RequestV2 {
	capn_text psk;
	uint32_t version;
	enum RouteV2 route;
	enum RequestV2_which which;
	capnp_nowarn union {
		PingV2_ptr ping;
		ResolveProgramV2_ptr resolveProgram;
		ShareProgramV2_ptr shareProgram;
	};
};

static const size_t RequestV2_word_count = 1;

static const size_t RequestV2_pointer_count = 2;

static const size_t RequestV2_struct_bytes_count = 24;


capn_text RequestV2_get_psk(RequestV2_ptr p);

uint32_t RequestV2_get_version(RequestV2_ptr p);

enum RouteV2 RequestV2_get_route(RequestV2_ptr p);

void RequestV2_set_psk(RequestV2_ptr p, capn_text psk);

void RequestV2_set_version(RequestV2_ptr p, uint32_t version);

void RequestV2_set_route(RequestV2_ptr p, enum RouteV2 route);

struct MessageV2 {
	capn_text text;
};

static const size_t MessageV2_word_count = 0;

static const size_t MessageV2_pointer_count = 1;

static const size_t MessageV2_struct_bytes_count = 8;


capn_text MessageV2_get_text(MessageV2_ptr p);

void MessageV2_set_text(MessageV2_ptr p, capn_text text);

struct ServerInfoV2 {
	capn_list16 supportedCodecs;
	uint32_t minVersion;
	uint32_t maxVersion;
	unsigned keenhashEnabled : 1;
	unsigned decompilerRequired : 1;
	capn_text modelVersion;
	capn_text indexVersion;
	unsigned tlsRequired : 1;
};

static const size_t ServerInfoV2_word_count = 2;

static const size_t ServerInfoV2_pointer_count = 3;

static const size_t ServerInfoV2_struct_bytes_count = 40;


capn_list16 ServerInfoV2_get_supportedCodecs(ServerInfoV2_ptr p);

uint32_t ServerInfoV2_get_minVersion(ServerInfoV2_ptr p);

uint32_t ServerInfoV2_get_maxVersion(ServerInfoV2_ptr p);

unsigned ServerInfoV2_get_keenhashEnabled(ServerInfoV2_ptr p);

unsigned ServerInfoV2_get_decompilerRequired(ServerInfoV2_ptr p);

capn_text ServerInfoV2_get_modelVersion(ServerInfoV2_ptr p);

capn_text ServerInfoV2_get_indexVersion(ServerInfoV2_ptr p);

unsigned ServerInfoV2_get_tlsRequired(ServerInfoV2_ptr p);

void ServerInfoV2_set_supportedCodecs(ServerInfoV2_ptr p, capn_list16 supportedCodecs);

void ServerInfoV2_set_minVersion(ServerInfoV2_ptr p, uint32_t minVersion);

void ServerInfoV2_set_maxVersion(ServerInfoV2_ptr p, uint32_t maxVersion);

void ServerInfoV2_set_keenhashEnabled(ServerInfoV2_ptr p, unsigned keenhashEnabled);

void ServerInfoV2_set_decompilerRequired(ServerInfoV2_ptr p, unsigned decompilerRequired);

void ServerInfoV2_set_modelVersion(ServerInfoV2_ptr p, capn_text modelVersion);

void ServerInfoV2_set_indexVersion(ServerInfoV2_ptr p, capn_text indexVersion);

void ServerInfoV2_set_tlsRequired(ServerInfoV2_ptr p, unsigned tlsRequired);

struct SymbolMatchV2 {
	uint64_t addr;
	SymbolV2_ptr symbol;
	float confidence;
	unsigned exact : 1;
	capn_text matchedBinaryId;
	capn_text matchedBy;
	uint64_t offset;
	uint32_t size;
};

static const size_t SymbolMatchV2_word_count = 4;

static const size_t SymbolMatchV2_pointer_count = 3;

static const size_t SymbolMatchV2_struct_bytes_count = 56;


uint64_t SymbolMatchV2_get_addr(SymbolMatchV2_ptr p);

SymbolV2_ptr SymbolMatchV2_get_symbol(SymbolMatchV2_ptr p);

float SymbolMatchV2_get_confidence(SymbolMatchV2_ptr p);

unsigned SymbolMatchV2_get_exact(SymbolMatchV2_ptr p);

capn_text SymbolMatchV2_get_matchedBinaryId(SymbolMatchV2_ptr p);

capn_text SymbolMatchV2_get_matchedBy(SymbolMatchV2_ptr p);

uint64_t SymbolMatchV2_get_offset(SymbolMatchV2_ptr p);

uint32_t SymbolMatchV2_get_size(SymbolMatchV2_ptr p);

void SymbolMatchV2_set_addr(SymbolMatchV2_ptr p, uint64_t addr);

void SymbolMatchV2_set_symbol(SymbolMatchV2_ptr p, SymbolV2_ptr symbol);

void SymbolMatchV2_set_confidence(SymbolMatchV2_ptr p, float confidence);

void SymbolMatchV2_set_exact(SymbolMatchV2_ptr p, unsigned exact);

void SymbolMatchV2_set_matchedBinaryId(SymbolMatchV2_ptr p, capn_text matchedBinaryId);

void SymbolMatchV2_set_matchedBy(SymbolMatchV2_ptr p, capn_text matchedBy);

void SymbolMatchV2_set_offset(SymbolMatchV2_ptr p, uint64_t offset);

void SymbolMatchV2_set_size(SymbolMatchV2_ptr p, uint32_t size);

struct ResolveResultV2 {
	HintV2_list hints;
	SymbolMatchV2_list symbols;
	capn_ptr candidateBinaryIds;
	capn_text modelVersion;
	capn_text indexVersion;
};

static const size_t ResolveResultV2_word_count = 0;

static const size_t ResolveResultV2_pointer_count = 5;

static const size_t ResolveResultV2_struct_bytes_count = 40;


HintV2_list ResolveResultV2_get_hints(ResolveResultV2_ptr p);

SymbolMatchV2_list ResolveResultV2_get_symbols(ResolveResultV2_ptr p);

capn_ptr ResolveResultV2_get_candidateBinaryIds(ResolveResultV2_ptr p);

capn_text ResolveResultV2_get_modelVersion(ResolveResultV2_ptr p);

capn_text ResolveResultV2_get_indexVersion(ResolveResultV2_ptr p);

void ResolveResultV2_set_hints(ResolveResultV2_ptr p, HintV2_list hints);

void ResolveResultV2_set_symbols(ResolveResultV2_ptr p, SymbolMatchV2_list symbols);

void ResolveResultV2_set_candidateBinaryIds(ResolveResultV2_ptr p, capn_ptr candidateBinaryIds);

void ResolveResultV2_set_modelVersion(ResolveResultV2_ptr p, capn_text modelVersion);

void ResolveResultV2_set_indexVersion(ResolveResultV2_ptr p, capn_text indexVersion);

struct ShareResultV2 {
	capn_text binaryId;
	uint32_t ingestedFunctions;
	uint32_t candidateCount;
	capn_text modelVersion;
	capn_text indexVersion;
};

static const size_t ShareResultV2_word_count = 1;

static const size_t ShareResultV2_pointer_count = 3;

static const size_t ShareResultV2_struct_bytes_count = 32;


capn_text ShareResultV2_get_binaryId(ShareResultV2_ptr p);

uint32_t ShareResultV2_get_ingestedFunctions(ShareResultV2_ptr p);

uint32_t ShareResultV2_get_candidateCount(ShareResultV2_ptr p);

capn_text ShareResultV2_get_modelVersion(ShareResultV2_ptr p);

capn_text ShareResultV2_get_indexVersion(ShareResultV2_ptr p);

void ShareResultV2_set_binaryId(ShareResultV2_ptr p, capn_text binaryId);

void ShareResultV2_set_ingestedFunctions(ShareResultV2_ptr p, uint32_t ingestedFunctions);

void ShareResultV2_set_candidateCount(ShareResultV2_ptr p, uint32_t candidateCount);

void ShareResultV2_set_modelVersion(ShareResultV2_ptr p, capn_text modelVersion);

void ShareResultV2_set_indexVersion(ShareResultV2_ptr p, capn_text indexVersion);
enum ResponseV2_which {
	ResponseV2_message = 0,
	ResponseV2_serverInfo = 1,
	ResponseV2_resolveResult = 2,
	ResponseV2_shareResult = 3
};

struct ResponseV2 {
	enum StatusV2 status;
	enum ResponseV2_which which;
	capnp_nowarn union {
		MessageV2_ptr message;
		ServerInfoV2_ptr serverInfo;
		ResolveResultV2_ptr resolveResult;
		ShareResultV2_ptr shareResult;
	};
};

static const size_t ResponseV2_word_count = 1;

static const size_t ResponseV2_pointer_count = 1;

static const size_t ResponseV2_struct_bytes_count = 16;


enum StatusV2 ResponseV2_get_status(ResponseV2_ptr p);

void ResponseV2_set_status(ResponseV2_ptr p, enum StatusV2 status);

SectionHashV2_ptr new_SectionHashV2(struct capn_segment*);
HintV2_ptr new_HintV2(struct capn_segment*);
SymbolV2_ptr new_SymbolV2(struct capn_segment*);
FunctionBundleV2_ptr new_FunctionBundleV2(struct capn_segment*);
ProgramBundleV2_ptr new_ProgramBundleV2(struct capn_segment*);
PingV2_ptr new_PingV2(struct capn_segment*);
ResolveProgramV2_ptr new_ResolveProgramV2(struct capn_segment*);
ShareProgramV2_ptr new_ShareProgramV2(struct capn_segment*);
RequestV2_ptr new_RequestV2(struct capn_segment*);
MessageV2_ptr new_MessageV2(struct capn_segment*);
ServerInfoV2_ptr new_ServerInfoV2(struct capn_segment*);
SymbolMatchV2_ptr new_SymbolMatchV2(struct capn_segment*);
ResolveResultV2_ptr new_ResolveResultV2(struct capn_segment*);
ShareResultV2_ptr new_ShareResultV2(struct capn_segment*);
ResponseV2_ptr new_ResponseV2(struct capn_segment*);

SectionHashV2_list new_SectionHashV2_list(struct capn_segment*, int len);
HintV2_list new_HintV2_list(struct capn_segment*, int len);
SymbolV2_list new_SymbolV2_list(struct capn_segment*, int len);
FunctionBundleV2_list new_FunctionBundleV2_list(struct capn_segment*, int len);
ProgramBundleV2_list new_ProgramBundleV2_list(struct capn_segment*, int len);
PingV2_list new_PingV2_list(struct capn_segment*, int len);
ResolveProgramV2_list new_ResolveProgramV2_list(struct capn_segment*, int len);
ShareProgramV2_list new_ShareProgramV2_list(struct capn_segment*, int len);
RequestV2_list new_RequestV2_list(struct capn_segment*, int len);
MessageV2_list new_MessageV2_list(struct capn_segment*, int len);
ServerInfoV2_list new_ServerInfoV2_list(struct capn_segment*, int len);
SymbolMatchV2_list new_SymbolMatchV2_list(struct capn_segment*, int len);
ResolveResultV2_list new_ResolveResultV2_list(struct capn_segment*, int len);
ShareResultV2_list new_ShareResultV2_list(struct capn_segment*, int len);
ResponseV2_list new_ResponseV2_list(struct capn_segment*, int len);

void read_SectionHashV2(struct SectionHashV2*, SectionHashV2_ptr);
void read_HintV2(struct HintV2*, HintV2_ptr);
void read_SymbolV2(struct SymbolV2*, SymbolV2_ptr);
void read_FunctionBundleV2(struct FunctionBundleV2*, FunctionBundleV2_ptr);
void read_ProgramBundleV2(struct ProgramBundleV2*, ProgramBundleV2_ptr);
void read_PingV2(struct PingV2*, PingV2_ptr);
void read_ResolveProgramV2(struct ResolveProgramV2*, ResolveProgramV2_ptr);
void read_ShareProgramV2(struct ShareProgramV2*, ShareProgramV2_ptr);
void read_RequestV2(struct RequestV2*, RequestV2_ptr);
void read_MessageV2(struct MessageV2*, MessageV2_ptr);
void read_ServerInfoV2(struct ServerInfoV2*, ServerInfoV2_ptr);
void read_SymbolMatchV2(struct SymbolMatchV2*, SymbolMatchV2_ptr);
void read_ResolveResultV2(struct ResolveResultV2*, ResolveResultV2_ptr);
void read_ShareResultV2(struct ShareResultV2*, ShareResultV2_ptr);
void read_ResponseV2(struct ResponseV2*, ResponseV2_ptr);

void write_SectionHashV2(const struct SectionHashV2*, SectionHashV2_ptr);
void write_HintV2(const struct HintV2*, HintV2_ptr);
void write_SymbolV2(const struct SymbolV2*, SymbolV2_ptr);
void write_FunctionBundleV2(const struct FunctionBundleV2*, FunctionBundleV2_ptr);
void write_ProgramBundleV2(const struct ProgramBundleV2*, ProgramBundleV2_ptr);
void write_PingV2(const struct PingV2*, PingV2_ptr);
void write_ResolveProgramV2(const struct ResolveProgramV2*, ResolveProgramV2_ptr);
void write_ShareProgramV2(const struct ShareProgramV2*, ShareProgramV2_ptr);
void write_RequestV2(const struct RequestV2*, RequestV2_ptr);
void write_MessageV2(const struct MessageV2*, MessageV2_ptr);
void write_ServerInfoV2(const struct ServerInfoV2*, ServerInfoV2_ptr);
void write_SymbolMatchV2(const struct SymbolMatchV2*, SymbolMatchV2_ptr);
void write_ResolveResultV2(const struct ResolveResultV2*, ResolveResultV2_ptr);
void write_ShareResultV2(const struct ShareResultV2*, ShareResultV2_ptr);
void write_ResponseV2(const struct ResponseV2*, ResponseV2_ptr);

void get_SectionHashV2(struct SectionHashV2*, SectionHashV2_list, int i);
void get_HintV2(struct HintV2*, HintV2_list, int i);
void get_SymbolV2(struct SymbolV2*, SymbolV2_list, int i);
void get_FunctionBundleV2(struct FunctionBundleV2*, FunctionBundleV2_list, int i);
void get_ProgramBundleV2(struct ProgramBundleV2*, ProgramBundleV2_list, int i);
void get_PingV2(struct PingV2*, PingV2_list, int i);
void get_ResolveProgramV2(struct ResolveProgramV2*, ResolveProgramV2_list, int i);
void get_ShareProgramV2(struct ShareProgramV2*, ShareProgramV2_list, int i);
void get_RequestV2(struct RequestV2*, RequestV2_list, int i);
void get_MessageV2(struct MessageV2*, MessageV2_list, int i);
void get_ServerInfoV2(struct ServerInfoV2*, ServerInfoV2_list, int i);
void get_SymbolMatchV2(struct SymbolMatchV2*, SymbolMatchV2_list, int i);
void get_ResolveResultV2(struct ResolveResultV2*, ResolveResultV2_list, int i);
void get_ShareResultV2(struct ShareResultV2*, ShareResultV2_list, int i);
void get_ResponseV2(struct ResponseV2*, ResponseV2_list, int i);

void set_SectionHashV2(const struct SectionHashV2*, SectionHashV2_list, int i);
void set_HintV2(const struct HintV2*, HintV2_list, int i);
void set_SymbolV2(const struct SymbolV2*, SymbolV2_list, int i);
void set_FunctionBundleV2(const struct FunctionBundleV2*, FunctionBundleV2_list, int i);
void set_ProgramBundleV2(const struct ProgramBundleV2*, ProgramBundleV2_list, int i);
void set_PingV2(const struct PingV2*, PingV2_list, int i);
void set_ResolveProgramV2(const struct ResolveProgramV2*, ResolveProgramV2_list, int i);
void set_ShareProgramV2(const struct ShareProgramV2*, ShareProgramV2_list, int i);
void set_RequestV2(const struct RequestV2*, RequestV2_list, int i);
void set_MessageV2(const struct MessageV2*, MessageV2_list, int i);
void set_ServerInfoV2(const struct ServerInfoV2*, ServerInfoV2_list, int i);
void set_SymbolMatchV2(const struct SymbolMatchV2*, SymbolMatchV2_list, int i);
void set_ResolveResultV2(const struct ResolveResultV2*, ResolveResultV2_list, int i);
void set_ShareResultV2(const struct ShareResultV2*, ShareResultV2_list, int i);
void set_ResponseV2(const struct ResponseV2*, ResponseV2_list, int i);

#ifdef __cplusplus
}
#endif
#endif
