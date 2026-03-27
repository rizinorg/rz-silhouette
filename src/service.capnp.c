#include "service.capnp.h"
/* AUTO GENERATED - DO NOT EDIT */
#ifdef __GNUC__
# define capnp_unused __attribute__((unused))
# define capnp_use(x) (void) (x);
#else
# define capnp_unused
# define capnp_use(x)
#endif

static const capn_text capn_val0 = {0,"",0};

SectionHashV2_ptr new_SectionHashV2(struct capn_segment *s) {
	SectionHashV2_ptr p;
	p.p = capn_new_struct(s, 16, 2);
	return p;
}
SectionHashV2_list new_SectionHashV2_list(struct capn_segment *s, int len) {
	SectionHashV2_list p;
	p.p = capn_new_list(s, len, 16, 2);
	return p;
}
void read_SectionHashV2(struct SectionHashV2 *s capnp_unused, SectionHashV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->size = capn_read32(p.p, 0);
	s->paddr = capn_read64(p.p, 8);
	s->digest = capn_get_data(p.p, 0);
	s->name = capn_get_text(p.p, 1, capn_val0);
}
void write_SectionHashV2(const struct SectionHashV2 *s capnp_unused, SectionHashV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->size);
	capn_write64(p.p, 8, s->paddr);
	capn_setp(p.p, 0, s->digest.p);
	capn_set_text(p.p, 1, s->name);
}
void get_SectionHashV2(struct SectionHashV2 *s, SectionHashV2_list l, int i) {
	SectionHashV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SectionHashV2(s, p);
}
void set_SectionHashV2(const struct SectionHashV2 *s, SectionHashV2_list l, int i) {
	SectionHashV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SectionHashV2(s, p);
}

uint32_t SectionHashV2_get_size(SectionHashV2_ptr p)
{
	uint32_t size;
	size = capn_read32(p.p, 0);
	return size;
}

uint64_t SectionHashV2_get_paddr(SectionHashV2_ptr p)
{
	uint64_t paddr;
	paddr = capn_read64(p.p, 8);
	return paddr;
}

capn_data SectionHashV2_get_digest(SectionHashV2_ptr p)
{
	capn_data digest;
	digest = capn_get_data(p.p, 0);
	return digest;
}

capn_text SectionHashV2_get_name(SectionHashV2_ptr p)
{
	capn_text name;
	name = capn_get_text(p.p, 1, capn_val0);
	return name;
}

void SectionHashV2_set_size(SectionHashV2_ptr p, uint32_t size)
{
	capn_write32(p.p, 0, size);
}

void SectionHashV2_set_paddr(SectionHashV2_ptr p, uint64_t paddr)
{
	capn_write64(p.p, 8, paddr);
}

void SectionHashV2_set_digest(SectionHashV2_ptr p, capn_data digest)
{
	capn_setp(p.p, 0, digest.p);
}

void SectionHashV2_set_name(SectionHashV2_ptr p, capn_text name)
{
	capn_set_text(p.p, 1, name);
}

HintV2_ptr new_HintV2(struct capn_segment *s) {
	HintV2_ptr p;
	p.p = capn_new_struct(s, 16, 1);
	return p;
}
HintV2_list new_HintV2_list(struct capn_segment *s, int len) {
	HintV2_list p;
	p.p = capn_new_list(s, len, 16, 1);
	return p;
}
void read_HintV2(struct HintV2 *s capnp_unused, HintV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->bits = capn_read32(p.p, 0);
	s->offset = capn_read64(p.p, 8);
	s->confidence = capn_to_f32(capn_read32(p.p, 4));
	s->matchedBinaryId = capn_get_text(p.p, 0, capn_val0);
}
void write_HintV2(const struct HintV2 *s capnp_unused, HintV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->bits);
	capn_write64(p.p, 8, s->offset);
	capn_write32(p.p, 4, capn_from_f32(s->confidence));
	capn_set_text(p.p, 0, s->matchedBinaryId);
}
void get_HintV2(struct HintV2 *s, HintV2_list l, int i) {
	HintV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_HintV2(s, p);
}
void set_HintV2(const struct HintV2 *s, HintV2_list l, int i) {
	HintV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_HintV2(s, p);
}

uint32_t HintV2_get_bits(HintV2_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 0);
	return bits;
}

uint64_t HintV2_get_offset(HintV2_ptr p)
{
	uint64_t offset;
	offset = capn_read64(p.p, 8);
	return offset;
}

float HintV2_get_confidence(HintV2_ptr p)
{
	float confidence;
	confidence = capn_to_f32(capn_read32(p.p, 4));
	return confidence;
}

capn_text HintV2_get_matchedBinaryId(HintV2_ptr p)
{
	capn_text matchedBinaryId;
	matchedBinaryId = capn_get_text(p.p, 0, capn_val0);
	return matchedBinaryId;
}

void HintV2_set_bits(HintV2_ptr p, uint32_t bits)
{
	capn_write32(p.p, 0, bits);
}

void HintV2_set_offset(HintV2_ptr p, uint64_t offset)
{
	capn_write64(p.p, 8, offset);
}

void HintV2_set_confidence(HintV2_ptr p, float confidence)
{
	capn_write32(p.p, 4, capn_from_f32(confidence));
}

void HintV2_set_matchedBinaryId(HintV2_ptr p, capn_text matchedBinaryId)
{
	capn_set_text(p.p, 0, matchedBinaryId);
}

SymbolV2_ptr new_SymbolV2(struct capn_segment *s) {
	SymbolV2_ptr p;
	p.p = capn_new_struct(s, 8, 3);
	return p;
}
SymbolV2_list new_SymbolV2_list(struct capn_segment *s, int len) {
	SymbolV2_list p;
	p.p = capn_new_list(s, len, 8, 3);
	return p;
}
void read_SymbolV2(struct SymbolV2 *s capnp_unused, SymbolV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->name = capn_get_text(p.p, 0, capn_val0);
	s->signature = capn_get_text(p.p, 1, capn_val0);
	s->callconv = capn_get_text(p.p, 2, capn_val0);
	s->bits = capn_read32(p.p, 0);
}
void write_SymbolV2(const struct SymbolV2 *s capnp_unused, SymbolV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->name);
	capn_set_text(p.p, 1, s->signature);
	capn_set_text(p.p, 2, s->callconv);
	capn_write32(p.p, 0, s->bits);
}
void get_SymbolV2(struct SymbolV2 *s, SymbolV2_list l, int i) {
	SymbolV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SymbolV2(s, p);
}
void set_SymbolV2(const struct SymbolV2 *s, SymbolV2_list l, int i) {
	SymbolV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SymbolV2(s, p);
}

capn_text SymbolV2_get_name(SymbolV2_ptr p)
{
	capn_text name;
	name = capn_get_text(p.p, 0, capn_val0);
	return name;
}

capn_text SymbolV2_get_signature(SymbolV2_ptr p)
{
	capn_text signature;
	signature = capn_get_text(p.p, 1, capn_val0);
	return signature;
}

capn_text SymbolV2_get_callconv(SymbolV2_ptr p)
{
	capn_text callconv;
	callconv = capn_get_text(p.p, 2, capn_val0);
	return callconv;
}

uint32_t SymbolV2_get_bits(SymbolV2_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 0);
	return bits;
}

void SymbolV2_set_name(SymbolV2_ptr p, capn_text name)
{
	capn_set_text(p.p, 0, name);
}

void SymbolV2_set_signature(SymbolV2_ptr p, capn_text signature)
{
	capn_set_text(p.p, 1, signature);
}

void SymbolV2_set_callconv(SymbolV2_ptr p, capn_text callconv)
{
	capn_set_text(p.p, 2, callconv);
}

void SymbolV2_set_bits(SymbolV2_ptr p, uint32_t bits)
{
	capn_write32(p.p, 0, bits);
}

FunctionBundleV2_ptr new_FunctionBundleV2(struct capn_segment *s) {
	FunctionBundleV2_ptr p;
	p.p = capn_new_struct(s, 48, 9);
	return p;
}
FunctionBundleV2_list new_FunctionBundleV2_list(struct capn_segment *s, int len) {
	FunctionBundleV2_list p;
	p.p = capn_new_list(s, len, 48, 9);
	return p;
}
void read_FunctionBundleV2(struct FunctionBundleV2 *s capnp_unused, FunctionBundleV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->addr = capn_read64(p.p, 0);
	s->size = capn_read32(p.p, 8);
	s->bits = capn_read32(p.p, 12);
	s->arch = capn_get_text(p.p, 0, capn_val0);
	s->length = capn_read32(p.p, 16);
	s->digest = capn_get_data(p.p, 1);
	s->sectionName = capn_get_text(p.p, 2, capn_val0);
	s->sectionPaddr = capn_read64(p.p, 24);
	s->loc = capn_read32(p.p, 20);
	s->nos = capn_read32(p.p, 32);
	s->pseudocode = capn_get_text(p.p, 3, capn_val0);
	s->calls.p = capn_getp(p.p, 4, 0);
	s->name = capn_get_text(p.p, 5, capn_val0);
	s->signature = capn_get_text(p.p, 6, capn_val0);
	s->callconv = capn_get_text(p.p, 7, capn_val0);
	s->pseudocodeSource = capn_get_text(p.p, 8, capn_val0);
	s->sectionOffset = capn_read64(p.p, 40);
}
void write_FunctionBundleV2(const struct FunctionBundleV2 *s capnp_unused, FunctionBundleV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write64(p.p, 0, s->addr);
	capn_write32(p.p, 8, s->size);
	capn_write32(p.p, 12, s->bits);
	capn_set_text(p.p, 0, s->arch);
	capn_write32(p.p, 16, s->length);
	capn_setp(p.p, 1, s->digest.p);
	capn_set_text(p.p, 2, s->sectionName);
	capn_write64(p.p, 24, s->sectionPaddr);
	capn_write32(p.p, 20, s->loc);
	capn_write32(p.p, 32, s->nos);
	capn_set_text(p.p, 3, s->pseudocode);
	capn_setp(p.p, 4, s->calls.p);
	capn_set_text(p.p, 5, s->name);
	capn_set_text(p.p, 6, s->signature);
	capn_set_text(p.p, 7, s->callconv);
	capn_set_text(p.p, 8, s->pseudocodeSource);
	capn_write64(p.p, 40, s->sectionOffset);
}
void get_FunctionBundleV2(struct FunctionBundleV2 *s, FunctionBundleV2_list l, int i) {
	FunctionBundleV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_FunctionBundleV2(s, p);
}
void set_FunctionBundleV2(const struct FunctionBundleV2 *s, FunctionBundleV2_list l, int i) {
	FunctionBundleV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_FunctionBundleV2(s, p);
}

uint64_t FunctionBundleV2_get_addr(FunctionBundleV2_ptr p)
{
	uint64_t addr;
	addr = capn_read64(p.p, 0);
	return addr;
}

uint32_t FunctionBundleV2_get_size(FunctionBundleV2_ptr p)
{
	uint32_t size;
	size = capn_read32(p.p, 8);
	return size;
}

uint32_t FunctionBundleV2_get_bits(FunctionBundleV2_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 12);
	return bits;
}

capn_text FunctionBundleV2_get_arch(FunctionBundleV2_ptr p)
{
	capn_text arch;
	arch = capn_get_text(p.p, 0, capn_val0);
	return arch;
}

uint32_t FunctionBundleV2_get_length(FunctionBundleV2_ptr p)
{
	uint32_t length;
	length = capn_read32(p.p, 16);
	return length;
}

capn_data FunctionBundleV2_get_digest(FunctionBundleV2_ptr p)
{
	capn_data digest;
	digest = capn_get_data(p.p, 1);
	return digest;
}

capn_text FunctionBundleV2_get_sectionName(FunctionBundleV2_ptr p)
{
	capn_text sectionName;
	sectionName = capn_get_text(p.p, 2, capn_val0);
	return sectionName;
}

uint64_t FunctionBundleV2_get_sectionPaddr(FunctionBundleV2_ptr p)
{
	uint64_t sectionPaddr;
	sectionPaddr = capn_read64(p.p, 24);
	return sectionPaddr;
}

uint32_t FunctionBundleV2_get_loc(FunctionBundleV2_ptr p)
{
	uint32_t loc;
	loc = capn_read32(p.p, 20);
	return loc;
}

uint32_t FunctionBundleV2_get_nos(FunctionBundleV2_ptr p)
{
	uint32_t nos;
	nos = capn_read32(p.p, 32);
	return nos;
}

capn_text FunctionBundleV2_get_pseudocode(FunctionBundleV2_ptr p)
{
	capn_text pseudocode;
	pseudocode = capn_get_text(p.p, 3, capn_val0);
	return pseudocode;
}

capn_list64 FunctionBundleV2_get_calls(FunctionBundleV2_ptr p)
{
	capn_list64 calls;
	calls.p = capn_getp(p.p, 4, 0);
	return calls;
}

capn_text FunctionBundleV2_get_name(FunctionBundleV2_ptr p)
{
	capn_text name;
	name = capn_get_text(p.p, 5, capn_val0);
	return name;
}

capn_text FunctionBundleV2_get_signature(FunctionBundleV2_ptr p)
{
	capn_text signature;
	signature = capn_get_text(p.p, 6, capn_val0);
	return signature;
}

capn_text FunctionBundleV2_get_callconv(FunctionBundleV2_ptr p)
{
	capn_text callconv;
	callconv = capn_get_text(p.p, 7, capn_val0);
	return callconv;
}

capn_text FunctionBundleV2_get_pseudocodeSource(FunctionBundleV2_ptr p)
{
	capn_text pseudocodeSource;
	pseudocodeSource = capn_get_text(p.p, 8, capn_val0);
	return pseudocodeSource;
}

uint64_t FunctionBundleV2_get_sectionOffset(FunctionBundleV2_ptr p)
{
	uint64_t sectionOffset;
	sectionOffset = capn_read64(p.p, 40);
	return sectionOffset;
}

void FunctionBundleV2_set_addr(FunctionBundleV2_ptr p, uint64_t addr)
{
	capn_write64(p.p, 0, addr);
}

void FunctionBundleV2_set_size(FunctionBundleV2_ptr p, uint32_t size)
{
	capn_write32(p.p, 8, size);
}

void FunctionBundleV2_set_bits(FunctionBundleV2_ptr p, uint32_t bits)
{
	capn_write32(p.p, 12, bits);
}

void FunctionBundleV2_set_arch(FunctionBundleV2_ptr p, capn_text arch)
{
	capn_set_text(p.p, 0, arch);
}

void FunctionBundleV2_set_length(FunctionBundleV2_ptr p, uint32_t length)
{
	capn_write32(p.p, 16, length);
}

void FunctionBundleV2_set_digest(FunctionBundleV2_ptr p, capn_data digest)
{
	capn_setp(p.p, 1, digest.p);
}

void FunctionBundleV2_set_sectionName(FunctionBundleV2_ptr p, capn_text sectionName)
{
	capn_set_text(p.p, 2, sectionName);
}

void FunctionBundleV2_set_sectionPaddr(FunctionBundleV2_ptr p, uint64_t sectionPaddr)
{
	capn_write64(p.p, 24, sectionPaddr);
}

void FunctionBundleV2_set_loc(FunctionBundleV2_ptr p, uint32_t loc)
{
	capn_write32(p.p, 20, loc);
}

void FunctionBundleV2_set_nos(FunctionBundleV2_ptr p, uint32_t nos)
{
	capn_write32(p.p, 32, nos);
}

void FunctionBundleV2_set_pseudocode(FunctionBundleV2_ptr p, capn_text pseudocode)
{
	capn_set_text(p.p, 3, pseudocode);
}

void FunctionBundleV2_set_calls(FunctionBundleV2_ptr p, capn_list64 calls)
{
	capn_setp(p.p, 4, calls.p);
}

void FunctionBundleV2_set_name(FunctionBundleV2_ptr p, capn_text name)
{
	capn_set_text(p.p, 5, name);
}

void FunctionBundleV2_set_signature(FunctionBundleV2_ptr p, capn_text signature)
{
	capn_set_text(p.p, 6, signature);
}

void FunctionBundleV2_set_callconv(FunctionBundleV2_ptr p, capn_text callconv)
{
	capn_set_text(p.p, 7, callconv);
}

void FunctionBundleV2_set_pseudocodeSource(FunctionBundleV2_ptr p, capn_text pseudocodeSource)
{
	capn_set_text(p.p, 8, pseudocodeSource);
}

void FunctionBundleV2_set_sectionOffset(FunctionBundleV2_ptr p, uint64_t sectionOffset)
{
	capn_write64(p.p, 40, sectionOffset);
}

ProgramBundleV2_ptr new_ProgramBundleV2(struct capn_segment *s) {
	ProgramBundleV2_ptr p;
	p.p = capn_new_struct(s, 8, 6);
	return p;
}
ProgramBundleV2_list new_ProgramBundleV2_list(struct capn_segment *s, int len) {
	ProgramBundleV2_list p;
	p.p = capn_new_list(s, len, 8, 6);
	return p;
}
void read_ProgramBundleV2(struct ProgramBundleV2 *s capnp_unused, ProgramBundleV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->binaryType = capn_get_text(p.p, 0, capn_val0);
	s->os = capn_get_text(p.p, 1, capn_val0);
	s->arch = capn_get_text(p.p, 2, capn_val0);
	s->bits = capn_read32(p.p, 0);
	s->binaryId = capn_get_text(p.p, 3, capn_val0);
	s->sections.p = capn_getp(p.p, 4, 0);
	s->functions.p = capn_getp(p.p, 5, 0);
	s->topk = capn_read32(p.p, 4);
}
void write_ProgramBundleV2(const struct ProgramBundleV2 *s capnp_unused, ProgramBundleV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->binaryType);
	capn_set_text(p.p, 1, s->os);
	capn_set_text(p.p, 2, s->arch);
	capn_write32(p.p, 0, s->bits);
	capn_set_text(p.p, 3, s->binaryId);
	capn_setp(p.p, 4, s->sections.p);
	capn_setp(p.p, 5, s->functions.p);
	capn_write32(p.p, 4, s->topk);
}
void get_ProgramBundleV2(struct ProgramBundleV2 *s, ProgramBundleV2_list l, int i) {
	ProgramBundleV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ProgramBundleV2(s, p);
}
void set_ProgramBundleV2(const struct ProgramBundleV2 *s, ProgramBundleV2_list l, int i) {
	ProgramBundleV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ProgramBundleV2(s, p);
}

capn_text ProgramBundleV2_get_binaryType(ProgramBundleV2_ptr p)
{
	capn_text binaryType;
	binaryType = capn_get_text(p.p, 0, capn_val0);
	return binaryType;
}

capn_text ProgramBundleV2_get_os(ProgramBundleV2_ptr p)
{
	capn_text os;
	os = capn_get_text(p.p, 1, capn_val0);
	return os;
}

capn_text ProgramBundleV2_get_arch(ProgramBundleV2_ptr p)
{
	capn_text arch;
	arch = capn_get_text(p.p, 2, capn_val0);
	return arch;
}

uint32_t ProgramBundleV2_get_bits(ProgramBundleV2_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 0);
	return bits;
}

capn_text ProgramBundleV2_get_binaryId(ProgramBundleV2_ptr p)
{
	capn_text binaryId;
	binaryId = capn_get_text(p.p, 3, capn_val0);
	return binaryId;
}

SectionHashV2_list ProgramBundleV2_get_sections(ProgramBundleV2_ptr p)
{
	SectionHashV2_list sections;
	sections.p = capn_getp(p.p, 4, 0);
	return sections;
}

FunctionBundleV2_list ProgramBundleV2_get_functions(ProgramBundleV2_ptr p)
{
	FunctionBundleV2_list functions;
	functions.p = capn_getp(p.p, 5, 0);
	return functions;
}

uint32_t ProgramBundleV2_get_topk(ProgramBundleV2_ptr p)
{
	uint32_t topk;
	topk = capn_read32(p.p, 4);
	return topk;
}

void ProgramBundleV2_set_binaryType(ProgramBundleV2_ptr p, capn_text binaryType)
{
	capn_set_text(p.p, 0, binaryType);
}

void ProgramBundleV2_set_os(ProgramBundleV2_ptr p, capn_text os)
{
	capn_set_text(p.p, 1, os);
}

void ProgramBundleV2_set_arch(ProgramBundleV2_ptr p, capn_text arch)
{
	capn_set_text(p.p, 2, arch);
}

void ProgramBundleV2_set_bits(ProgramBundleV2_ptr p, uint32_t bits)
{
	capn_write32(p.p, 0, bits);
}

void ProgramBundleV2_set_binaryId(ProgramBundleV2_ptr p, capn_text binaryId)
{
	capn_set_text(p.p, 3, binaryId);
}

void ProgramBundleV2_set_sections(ProgramBundleV2_ptr p, SectionHashV2_list sections)
{
	capn_setp(p.p, 4, sections.p);
}

void ProgramBundleV2_set_functions(ProgramBundleV2_ptr p, FunctionBundleV2_list functions)
{
	capn_setp(p.p, 5, functions.p);
}

void ProgramBundleV2_set_topk(ProgramBundleV2_ptr p, uint32_t topk)
{
	capn_write32(p.p, 4, topk);
}

PingV2_ptr new_PingV2(struct capn_segment *s) {
	PingV2_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
PingV2_list new_PingV2_list(struct capn_segment *s, int len) {
	PingV2_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_PingV2(struct PingV2 *s capnp_unused, PingV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->reserved = (capn_read8(p.p, 0) & 1) != 0;
}
void write_PingV2(const struct PingV2 *s capnp_unused, PingV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write1(p.p, 0, s->reserved != 0);
}
void get_PingV2(struct PingV2 *s, PingV2_list l, int i) {
	PingV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_PingV2(s, p);
}
void set_PingV2(const struct PingV2 *s, PingV2_list l, int i) {
	PingV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_PingV2(s, p);
}

unsigned PingV2_get_reserved(PingV2_ptr p)
{
	unsigned reserved;
	reserved = (capn_read8(p.p, 0) & 1) != 0;
	return reserved;
}

void PingV2_set_reserved(PingV2_ptr p, unsigned reserved)
{
	capn_write1(p.p, 0, reserved != 0);
}

ResolveProgramV2_ptr new_ResolveProgramV2(struct capn_segment *s) {
	ResolveProgramV2_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
ResolveProgramV2_list new_ResolveProgramV2_list(struct capn_segment *s, int len) {
	ResolveProgramV2_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_ResolveProgramV2(struct ResolveProgramV2 *s capnp_unused, ResolveProgramV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->program.p = capn_getp(p.p, 0, 0);
}
void write_ResolveProgramV2(const struct ResolveProgramV2 *s capnp_unused, ResolveProgramV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->program.p);
}
void get_ResolveProgramV2(struct ResolveProgramV2 *s, ResolveProgramV2_list l, int i) {
	ResolveProgramV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ResolveProgramV2(s, p);
}
void set_ResolveProgramV2(const struct ResolveProgramV2 *s, ResolveProgramV2_list l, int i) {
	ResolveProgramV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ResolveProgramV2(s, p);
}

ProgramBundleV2_ptr ResolveProgramV2_get_program(ResolveProgramV2_ptr p)
{
	ProgramBundleV2_ptr program;
	program.p = capn_getp(p.p, 0, 0);
	return program;
}

void ResolveProgramV2_set_program(ResolveProgramV2_ptr p, ProgramBundleV2_ptr program)
{
	capn_setp(p.p, 0, program.p);
}

ShareProgramV2_ptr new_ShareProgramV2(struct capn_segment *s) {
	ShareProgramV2_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
ShareProgramV2_list new_ShareProgramV2_list(struct capn_segment *s, int len) {
	ShareProgramV2_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_ShareProgramV2(struct ShareProgramV2 *s capnp_unused, ShareProgramV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->program.p = capn_getp(p.p, 0, 0);
}
void write_ShareProgramV2(const struct ShareProgramV2 *s capnp_unused, ShareProgramV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->program.p);
}
void get_ShareProgramV2(struct ShareProgramV2 *s, ShareProgramV2_list l, int i) {
	ShareProgramV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ShareProgramV2(s, p);
}
void set_ShareProgramV2(const struct ShareProgramV2 *s, ShareProgramV2_list l, int i) {
	ShareProgramV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ShareProgramV2(s, p);
}

ProgramBundleV2_ptr ShareProgramV2_get_program(ShareProgramV2_ptr p)
{
	ProgramBundleV2_ptr program;
	program.p = capn_getp(p.p, 0, 0);
	return program;
}

void ShareProgramV2_set_program(ShareProgramV2_ptr p, ProgramBundleV2_ptr program)
{
	capn_setp(p.p, 0, program.p);
}

RequestV2_ptr new_RequestV2(struct capn_segment *s) {
	RequestV2_ptr p;
	p.p = capn_new_struct(s, 8, 2);
	return p;
}
RequestV2_list new_RequestV2_list(struct capn_segment *s, int len) {
	RequestV2_list p;
	p.p = capn_new_list(s, len, 8, 2);
	return p;
}
void read_RequestV2(struct RequestV2 *s capnp_unused, RequestV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->psk = capn_get_text(p.p, 0, capn_val0);
	s->version = capn_read32(p.p, 0);
	s->route = (enum RouteV2)(int) capn_read16(p.p, 4);
	s->which = (enum RequestV2_which)(int) capn_read16(p.p, 6);
	switch (s->which) {
	case RequestV2_ping:
	case RequestV2_resolveProgram:
	case RequestV2_shareProgram:
		s->shareProgram.p = capn_getp(p.p, 1, 0);
		break;
	default:
		break;
	}
}
void write_RequestV2(const struct RequestV2 *s capnp_unused, RequestV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->psk);
	capn_write32(p.p, 0, s->version);
	capn_write16(p.p, 4, (uint16_t) (s->route));
	capn_write16(p.p, 6, s->which);
	switch (s->which) {
	case RequestV2_ping:
	case RequestV2_resolveProgram:
	case RequestV2_shareProgram:
		capn_setp(p.p, 1, s->shareProgram.p);
		break;
	default:
		break;
	}
}
void get_RequestV2(struct RequestV2 *s, RequestV2_list l, int i) {
	RequestV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_RequestV2(s, p);
}
void set_RequestV2(const struct RequestV2 *s, RequestV2_list l, int i) {
	RequestV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_RequestV2(s, p);
}

capn_text RequestV2_get_psk(RequestV2_ptr p)
{
	capn_text psk;
	psk = capn_get_text(p.p, 0, capn_val0);
	return psk;
}

uint32_t RequestV2_get_version(RequestV2_ptr p)
{
	uint32_t version;
	version = capn_read32(p.p, 0);
	return version;
}

enum RouteV2 RequestV2_get_route(RequestV2_ptr p)
{
	enum RouteV2 route;
	route = (enum RouteV2)(int) capn_read16(p.p, 4);
	return route;
}

void RequestV2_set_psk(RequestV2_ptr p, capn_text psk)
{
	capn_set_text(p.p, 0, psk);
}

void RequestV2_set_version(RequestV2_ptr p, uint32_t version)
{
	capn_write32(p.p, 0, version);
}

void RequestV2_set_route(RequestV2_ptr p, enum RouteV2 route)
{
	capn_write16(p.p, 4, (uint16_t) (route));
}

MessageV2_ptr new_MessageV2(struct capn_segment *s) {
	MessageV2_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
MessageV2_list new_MessageV2_list(struct capn_segment *s, int len) {
	MessageV2_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_MessageV2(struct MessageV2 *s capnp_unused, MessageV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->text = capn_get_text(p.p, 0, capn_val0);
}
void write_MessageV2(const struct MessageV2 *s capnp_unused, MessageV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->text);
}
void get_MessageV2(struct MessageV2 *s, MessageV2_list l, int i) {
	MessageV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_MessageV2(s, p);
}
void set_MessageV2(const struct MessageV2 *s, MessageV2_list l, int i) {
	MessageV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_MessageV2(s, p);
}

capn_text MessageV2_get_text(MessageV2_ptr p)
{
	capn_text text;
	text = capn_get_text(p.p, 0, capn_val0);
	return text;
}

void MessageV2_set_text(MessageV2_ptr p, capn_text text)
{
	capn_set_text(p.p, 0, text);
}

ServerInfoV2_ptr new_ServerInfoV2(struct capn_segment *s) {
	ServerInfoV2_ptr p;
	p.p = capn_new_struct(s, 16, 3);
	return p;
}
ServerInfoV2_list new_ServerInfoV2_list(struct capn_segment *s, int len) {
	ServerInfoV2_list p;
	p.p = capn_new_list(s, len, 16, 3);
	return p;
}
void read_ServerInfoV2(struct ServerInfoV2 *s capnp_unused, ServerInfoV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->supportedCodecs.p = capn_getp(p.p, 0, 0);
	s->minVersion = capn_read32(p.p, 0);
	s->maxVersion = capn_read32(p.p, 4);
	s->keenhashEnabled = (capn_read8(p.p, 8) & 1) != 0;
	s->decompilerRequired = (capn_read8(p.p, 8) & 2) != 0;
	s->modelVersion = capn_get_text(p.p, 1, capn_val0);
	s->indexVersion = capn_get_text(p.p, 2, capn_val0);
	s->tlsRequired = (capn_read8(p.p, 8) & 4) != 0;
}
void write_ServerInfoV2(const struct ServerInfoV2 *s capnp_unused, ServerInfoV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->supportedCodecs.p);
	capn_write32(p.p, 0, s->minVersion);
	capn_write32(p.p, 4, s->maxVersion);
	capn_write1(p.p, 64, s->keenhashEnabled != 0);
	capn_write1(p.p, 65, s->decompilerRequired != 0);
	capn_set_text(p.p, 1, s->modelVersion);
	capn_set_text(p.p, 2, s->indexVersion);
	capn_write1(p.p, 66, s->tlsRequired != 0);
}
void get_ServerInfoV2(struct ServerInfoV2 *s, ServerInfoV2_list l, int i) {
	ServerInfoV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ServerInfoV2(s, p);
}
void set_ServerInfoV2(const struct ServerInfoV2 *s, ServerInfoV2_list l, int i) {
	ServerInfoV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ServerInfoV2(s, p);
}

capn_list16 ServerInfoV2_get_supportedCodecs(ServerInfoV2_ptr p)
{
	capn_list16 supportedCodecs;
	supportedCodecs.p = capn_getp(p.p, 0, 0);
	return supportedCodecs;
}

uint32_t ServerInfoV2_get_minVersion(ServerInfoV2_ptr p)
{
	uint32_t minVersion;
	minVersion = capn_read32(p.p, 0);
	return minVersion;
}

uint32_t ServerInfoV2_get_maxVersion(ServerInfoV2_ptr p)
{
	uint32_t maxVersion;
	maxVersion = capn_read32(p.p, 4);
	return maxVersion;
}

unsigned ServerInfoV2_get_keenhashEnabled(ServerInfoV2_ptr p)
{
	unsigned keenhashEnabled;
	keenhashEnabled = (capn_read8(p.p, 8) & 1) != 0;
	return keenhashEnabled;
}

unsigned ServerInfoV2_get_decompilerRequired(ServerInfoV2_ptr p)
{
	unsigned decompilerRequired;
	decompilerRequired = (capn_read8(p.p, 8) & 2) != 0;
	return decompilerRequired;
}

capn_text ServerInfoV2_get_modelVersion(ServerInfoV2_ptr p)
{
	capn_text modelVersion;
	modelVersion = capn_get_text(p.p, 1, capn_val0);
	return modelVersion;
}

capn_text ServerInfoV2_get_indexVersion(ServerInfoV2_ptr p)
{
	capn_text indexVersion;
	indexVersion = capn_get_text(p.p, 2, capn_val0);
	return indexVersion;
}

unsigned ServerInfoV2_get_tlsRequired(ServerInfoV2_ptr p)
{
	unsigned tlsRequired;
	tlsRequired = (capn_read8(p.p, 8) & 4) != 0;
	return tlsRequired;
}

void ServerInfoV2_set_supportedCodecs(ServerInfoV2_ptr p, capn_list16 supportedCodecs)
{
	capn_setp(p.p, 0, supportedCodecs.p);
}

void ServerInfoV2_set_minVersion(ServerInfoV2_ptr p, uint32_t minVersion)
{
	capn_write32(p.p, 0, minVersion);
}

void ServerInfoV2_set_maxVersion(ServerInfoV2_ptr p, uint32_t maxVersion)
{
	capn_write32(p.p, 4, maxVersion);
}

void ServerInfoV2_set_keenhashEnabled(ServerInfoV2_ptr p, unsigned keenhashEnabled)
{
	capn_write1(p.p, 64, keenhashEnabled != 0);
}

void ServerInfoV2_set_decompilerRequired(ServerInfoV2_ptr p, unsigned decompilerRequired)
{
	capn_write1(p.p, 65, decompilerRequired != 0);
}

void ServerInfoV2_set_modelVersion(ServerInfoV2_ptr p, capn_text modelVersion)
{
	capn_set_text(p.p, 1, modelVersion);
}

void ServerInfoV2_set_indexVersion(ServerInfoV2_ptr p, capn_text indexVersion)
{
	capn_set_text(p.p, 2, indexVersion);
}

void ServerInfoV2_set_tlsRequired(ServerInfoV2_ptr p, unsigned tlsRequired)
{
	capn_write1(p.p, 66, tlsRequired != 0);
}

SymbolMatchV2_ptr new_SymbolMatchV2(struct capn_segment *s) {
	SymbolMatchV2_ptr p;
	p.p = capn_new_struct(s, 32, 3);
	return p;
}
SymbolMatchV2_list new_SymbolMatchV2_list(struct capn_segment *s, int len) {
	SymbolMatchV2_list p;
	p.p = capn_new_list(s, len, 32, 3);
	return p;
}
void read_SymbolMatchV2(struct SymbolMatchV2 *s capnp_unused, SymbolMatchV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->addr = capn_read64(p.p, 0);
	s->symbol.p = capn_getp(p.p, 0, 0);
	s->confidence = capn_to_f32(capn_read32(p.p, 8));
	s->exact = (capn_read8(p.p, 12) & 1) != 0;
	s->matchedBinaryId = capn_get_text(p.p, 1, capn_val0);
	s->matchedBy = capn_get_text(p.p, 2, capn_val0);
	s->offset = capn_read64(p.p, 16);
	s->size = capn_read32(p.p, 24);
}
void write_SymbolMatchV2(const struct SymbolMatchV2 *s capnp_unused, SymbolMatchV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write64(p.p, 0, s->addr);
	capn_setp(p.p, 0, s->symbol.p);
	capn_write32(p.p, 8, capn_from_f32(s->confidence));
	capn_write1(p.p, 96, s->exact != 0);
	capn_set_text(p.p, 1, s->matchedBinaryId);
	capn_set_text(p.p, 2, s->matchedBy);
	capn_write64(p.p, 16, s->offset);
	capn_write32(p.p, 24, s->size);
}
void get_SymbolMatchV2(struct SymbolMatchV2 *s, SymbolMatchV2_list l, int i) {
	SymbolMatchV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SymbolMatchV2(s, p);
}
void set_SymbolMatchV2(const struct SymbolMatchV2 *s, SymbolMatchV2_list l, int i) {
	SymbolMatchV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SymbolMatchV2(s, p);
}

uint64_t SymbolMatchV2_get_addr(SymbolMatchV2_ptr p)
{
	uint64_t addr;
	addr = capn_read64(p.p, 0);
	return addr;
}

SymbolV2_ptr SymbolMatchV2_get_symbol(SymbolMatchV2_ptr p)
{
	SymbolV2_ptr symbol;
	symbol.p = capn_getp(p.p, 0, 0);
	return symbol;
}

float SymbolMatchV2_get_confidence(SymbolMatchV2_ptr p)
{
	float confidence;
	confidence = capn_to_f32(capn_read32(p.p, 8));
	return confidence;
}

unsigned SymbolMatchV2_get_exact(SymbolMatchV2_ptr p)
{
	unsigned exact;
	exact = (capn_read8(p.p, 12) & 1) != 0;
	return exact;
}

capn_text SymbolMatchV2_get_matchedBinaryId(SymbolMatchV2_ptr p)
{
	capn_text matchedBinaryId;
	matchedBinaryId = capn_get_text(p.p, 1, capn_val0);
	return matchedBinaryId;
}

capn_text SymbolMatchV2_get_matchedBy(SymbolMatchV2_ptr p)
{
	capn_text matchedBy;
	matchedBy = capn_get_text(p.p, 2, capn_val0);
	return matchedBy;
}

uint64_t SymbolMatchV2_get_offset(SymbolMatchV2_ptr p)
{
	uint64_t offset;
	offset = capn_read64(p.p, 16);
	return offset;
}

uint32_t SymbolMatchV2_get_size(SymbolMatchV2_ptr p)
{
	uint32_t size;
	size = capn_read32(p.p, 24);
	return size;
}

void SymbolMatchV2_set_addr(SymbolMatchV2_ptr p, uint64_t addr)
{
	capn_write64(p.p, 0, addr);
}

void SymbolMatchV2_set_symbol(SymbolMatchV2_ptr p, SymbolV2_ptr symbol)
{
	capn_setp(p.p, 0, symbol.p);
}

void SymbolMatchV2_set_confidence(SymbolMatchV2_ptr p, float confidence)
{
	capn_write32(p.p, 8, capn_from_f32(confidence));
}

void SymbolMatchV2_set_exact(SymbolMatchV2_ptr p, unsigned exact)
{
	capn_write1(p.p, 96, exact != 0);
}

void SymbolMatchV2_set_matchedBinaryId(SymbolMatchV2_ptr p, capn_text matchedBinaryId)
{
	capn_set_text(p.p, 1, matchedBinaryId);
}

void SymbolMatchV2_set_matchedBy(SymbolMatchV2_ptr p, capn_text matchedBy)
{
	capn_set_text(p.p, 2, matchedBy);
}

void SymbolMatchV2_set_offset(SymbolMatchV2_ptr p, uint64_t offset)
{
	capn_write64(p.p, 16, offset);
}

void SymbolMatchV2_set_size(SymbolMatchV2_ptr p, uint32_t size)
{
	capn_write32(p.p, 24, size);
}

ResolveResultV2_ptr new_ResolveResultV2(struct capn_segment *s) {
	ResolveResultV2_ptr p;
	p.p = capn_new_struct(s, 0, 5);
	return p;
}
ResolveResultV2_list new_ResolveResultV2_list(struct capn_segment *s, int len) {
	ResolveResultV2_list p;
	p.p = capn_new_list(s, len, 0, 5);
	return p;
}
void read_ResolveResultV2(struct ResolveResultV2 *s capnp_unused, ResolveResultV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->hints.p = capn_getp(p.p, 0, 0);
	s->symbols.p = capn_getp(p.p, 1, 0);
	s->candidateBinaryIds = capn_getp(p.p, 2, 0);
	s->modelVersion = capn_get_text(p.p, 3, capn_val0);
	s->indexVersion = capn_get_text(p.p, 4, capn_val0);
}
void write_ResolveResultV2(const struct ResolveResultV2 *s capnp_unused, ResolveResultV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->hints.p);
	capn_setp(p.p, 1, s->symbols.p);
	capn_setp(p.p, 2, s->candidateBinaryIds);
	capn_set_text(p.p, 3, s->modelVersion);
	capn_set_text(p.p, 4, s->indexVersion);
}
void get_ResolveResultV2(struct ResolveResultV2 *s, ResolveResultV2_list l, int i) {
	ResolveResultV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ResolveResultV2(s, p);
}
void set_ResolveResultV2(const struct ResolveResultV2 *s, ResolveResultV2_list l, int i) {
	ResolveResultV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ResolveResultV2(s, p);
}

HintV2_list ResolveResultV2_get_hints(ResolveResultV2_ptr p)
{
	HintV2_list hints;
	hints.p = capn_getp(p.p, 0, 0);
	return hints;
}

SymbolMatchV2_list ResolveResultV2_get_symbols(ResolveResultV2_ptr p)
{
	SymbolMatchV2_list symbols;
	symbols.p = capn_getp(p.p, 1, 0);
	return symbols;
}

capn_ptr ResolveResultV2_get_candidateBinaryIds(ResolveResultV2_ptr p)
{
	capn_ptr candidateBinaryIds;
	candidateBinaryIds = capn_getp(p.p, 2, 0);
	return candidateBinaryIds;
}

capn_text ResolveResultV2_get_modelVersion(ResolveResultV2_ptr p)
{
	capn_text modelVersion;
	modelVersion = capn_get_text(p.p, 3, capn_val0);
	return modelVersion;
}

capn_text ResolveResultV2_get_indexVersion(ResolveResultV2_ptr p)
{
	capn_text indexVersion;
	indexVersion = capn_get_text(p.p, 4, capn_val0);
	return indexVersion;
}

void ResolveResultV2_set_hints(ResolveResultV2_ptr p, HintV2_list hints)
{
	capn_setp(p.p, 0, hints.p);
}

void ResolveResultV2_set_symbols(ResolveResultV2_ptr p, SymbolMatchV2_list symbols)
{
	capn_setp(p.p, 1, symbols.p);
}

void ResolveResultV2_set_candidateBinaryIds(ResolveResultV2_ptr p, capn_ptr candidateBinaryIds)
{
	capn_setp(p.p, 2, candidateBinaryIds);
}

void ResolveResultV2_set_modelVersion(ResolveResultV2_ptr p, capn_text modelVersion)
{
	capn_set_text(p.p, 3, modelVersion);
}

void ResolveResultV2_set_indexVersion(ResolveResultV2_ptr p, capn_text indexVersion)
{
	capn_set_text(p.p, 4, indexVersion);
}

ShareResultV2_ptr new_ShareResultV2(struct capn_segment *s) {
	ShareResultV2_ptr p;
	p.p = capn_new_struct(s, 8, 3);
	return p;
}
ShareResultV2_list new_ShareResultV2_list(struct capn_segment *s, int len) {
	ShareResultV2_list p;
	p.p = capn_new_list(s, len, 8, 3);
	return p;
}
void read_ShareResultV2(struct ShareResultV2 *s capnp_unused, ShareResultV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->binaryId = capn_get_text(p.p, 0, capn_val0);
	s->ingestedFunctions = capn_read32(p.p, 0);
	s->candidateCount = capn_read32(p.p, 4);
	s->modelVersion = capn_get_text(p.p, 1, capn_val0);
	s->indexVersion = capn_get_text(p.p, 2, capn_val0);
}
void write_ShareResultV2(const struct ShareResultV2 *s capnp_unused, ShareResultV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->binaryId);
	capn_write32(p.p, 0, s->ingestedFunctions);
	capn_write32(p.p, 4, s->candidateCount);
	capn_set_text(p.p, 1, s->modelVersion);
	capn_set_text(p.p, 2, s->indexVersion);
}
void get_ShareResultV2(struct ShareResultV2 *s, ShareResultV2_list l, int i) {
	ShareResultV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ShareResultV2(s, p);
}
void set_ShareResultV2(const struct ShareResultV2 *s, ShareResultV2_list l, int i) {
	ShareResultV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ShareResultV2(s, p);
}

capn_text ShareResultV2_get_binaryId(ShareResultV2_ptr p)
{
	capn_text binaryId;
	binaryId = capn_get_text(p.p, 0, capn_val0);
	return binaryId;
}

uint32_t ShareResultV2_get_ingestedFunctions(ShareResultV2_ptr p)
{
	uint32_t ingestedFunctions;
	ingestedFunctions = capn_read32(p.p, 0);
	return ingestedFunctions;
}

uint32_t ShareResultV2_get_candidateCount(ShareResultV2_ptr p)
{
	uint32_t candidateCount;
	candidateCount = capn_read32(p.p, 4);
	return candidateCount;
}

capn_text ShareResultV2_get_modelVersion(ShareResultV2_ptr p)
{
	capn_text modelVersion;
	modelVersion = capn_get_text(p.p, 1, capn_val0);
	return modelVersion;
}

capn_text ShareResultV2_get_indexVersion(ShareResultV2_ptr p)
{
	capn_text indexVersion;
	indexVersion = capn_get_text(p.p, 2, capn_val0);
	return indexVersion;
}

void ShareResultV2_set_binaryId(ShareResultV2_ptr p, capn_text binaryId)
{
	capn_set_text(p.p, 0, binaryId);
}

void ShareResultV2_set_ingestedFunctions(ShareResultV2_ptr p, uint32_t ingestedFunctions)
{
	capn_write32(p.p, 0, ingestedFunctions);
}

void ShareResultV2_set_candidateCount(ShareResultV2_ptr p, uint32_t candidateCount)
{
	capn_write32(p.p, 4, candidateCount);
}

void ShareResultV2_set_modelVersion(ShareResultV2_ptr p, capn_text modelVersion)
{
	capn_set_text(p.p, 1, modelVersion);
}

void ShareResultV2_set_indexVersion(ShareResultV2_ptr p, capn_text indexVersion)
{
	capn_set_text(p.p, 2, indexVersion);
}

ResponseV2_ptr new_ResponseV2(struct capn_segment *s) {
	ResponseV2_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
ResponseV2_list new_ResponseV2_list(struct capn_segment *s, int len) {
	ResponseV2_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_ResponseV2(struct ResponseV2 *s capnp_unused, ResponseV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->status = (enum StatusV2)(int) capn_read16(p.p, 0);
	s->which = (enum ResponseV2_which)(int) capn_read16(p.p, 2);
	switch (s->which) {
	case ResponseV2_message:
	case ResponseV2_serverInfo:
	case ResponseV2_resolveResult:
	case ResponseV2_shareResult:
		s->shareResult.p = capn_getp(p.p, 0, 0);
		break;
	default:
		break;
	}
}
void write_ResponseV2(const struct ResponseV2 *s capnp_unused, ResponseV2_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write16(p.p, 0, (uint16_t) (s->status));
	capn_write16(p.p, 2, s->which);
	switch (s->which) {
	case ResponseV2_message:
	case ResponseV2_serverInfo:
	case ResponseV2_resolveResult:
	case ResponseV2_shareResult:
		capn_setp(p.p, 0, s->shareResult.p);
		break;
	default:
		break;
	}
}
void get_ResponseV2(struct ResponseV2 *s, ResponseV2_list l, int i) {
	ResponseV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_ResponseV2(s, p);
}
void set_ResponseV2(const struct ResponseV2 *s, ResponseV2_list l, int i) {
	ResponseV2_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_ResponseV2(s, p);
}

enum StatusV2 ResponseV2_get_status(ResponseV2_ptr p)
{
	enum StatusV2 status;
	status = (enum StatusV2)(int) capn_read16(p.p, 0);
	return status;
}

void ResponseV2_set_status(ResponseV2_ptr p, enum StatusV2 status)
{
	capn_write16(p.p, 0, (uint16_t) (status));
}
