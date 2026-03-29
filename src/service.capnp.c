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

SilSectionHash_ptr new_SilSectionHash(struct capn_segment *s) {
	SilSectionHash_ptr p;
	p.p = capn_new_struct(s, 16, 2);
	return p;
}
SilSectionHash_list new_SilSectionHash_list(struct capn_segment *s, int len) {
	SilSectionHash_list p;
	p.p = capn_new_list(s, len, 16, 2);
	return p;
}
void read_SilSectionHash(struct SilSectionHash *s capnp_unused, SilSectionHash_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->size = capn_read32(p.p, 0);
	s->paddr = capn_read64(p.p, 8);
	s->digest = capn_get_data(p.p, 0);
	s->name = capn_get_text(p.p, 1, capn_val0);
}
void write_SilSectionHash(const struct SilSectionHash *s capnp_unused, SilSectionHash_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->size);
	capn_write64(p.p, 8, s->paddr);
	capn_setp(p.p, 0, s->digest.p);
	capn_set_text(p.p, 1, s->name);
}
void get_SilSectionHash(struct SilSectionHash *s, SilSectionHash_list l, int i) {
	SilSectionHash_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilSectionHash(s, p);
}
void set_SilSectionHash(const struct SilSectionHash *s, SilSectionHash_list l, int i) {
	SilSectionHash_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilSectionHash(s, p);
}

uint32_t SilSectionHash_get_size(SilSectionHash_ptr p)
{
	uint32_t size;
	size = capn_read32(p.p, 0);
	return size;
}

uint64_t SilSectionHash_get_paddr(SilSectionHash_ptr p)
{
	uint64_t paddr;
	paddr = capn_read64(p.p, 8);
	return paddr;
}

capn_data SilSectionHash_get_digest(SilSectionHash_ptr p)
{
	capn_data digest;
	digest = capn_get_data(p.p, 0);
	return digest;
}

capn_text SilSectionHash_get_name(SilSectionHash_ptr p)
{
	capn_text name;
	name = capn_get_text(p.p, 1, capn_val0);
	return name;
}

void SilSectionHash_set_size(SilSectionHash_ptr p, uint32_t size)
{
	capn_write32(p.p, 0, size);
}

void SilSectionHash_set_paddr(SilSectionHash_ptr p, uint64_t paddr)
{
	capn_write64(p.p, 8, paddr);
}

void SilSectionHash_set_digest(SilSectionHash_ptr p, capn_data digest)
{
	capn_setp(p.p, 0, digest.p);
}

void SilSectionHash_set_name(SilSectionHash_ptr p, capn_text name)
{
	capn_set_text(p.p, 1, name);
}

SilHint_ptr new_SilHint(struct capn_segment *s) {
	SilHint_ptr p;
	p.p = capn_new_struct(s, 16, 0);
	return p;
}
SilHint_list new_SilHint_list(struct capn_segment *s, int len) {
	SilHint_list p;
	p.p = capn_new_list(s, len, 16, 0);
	return p;
}
void read_SilHint(struct SilHint *s capnp_unused, SilHint_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->bits = capn_read32(p.p, 0);
	s->offset = capn_read64(p.p, 8);
}
void write_SilHint(const struct SilHint *s capnp_unused, SilHint_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->bits);
	capn_write64(p.p, 8, s->offset);
}
void get_SilHint(struct SilHint *s, SilHint_list l, int i) {
	SilHint_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilHint(s, p);
}
void set_SilHint(const struct SilHint *s, SilHint_list l, int i) {
	SilHint_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilHint(s, p);
}

uint32_t SilHint_get_bits(SilHint_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 0);
	return bits;
}

uint64_t SilHint_get_offset(SilHint_ptr p)
{
	uint64_t offset;
	offset = capn_read64(p.p, 8);
	return offset;
}

void SilHint_set_bits(SilHint_ptr p, uint32_t bits)
{
	capn_write32(p.p, 0, bits);
}

void SilHint_set_offset(SilHint_ptr p, uint64_t offset)
{
	capn_write64(p.p, 8, offset);
}

SilSymbol_ptr new_SilSymbol(struct capn_segment *s) {
	SilSymbol_ptr p;
	p.p = capn_new_struct(s, 8, 3);
	return p;
}
SilSymbol_list new_SilSymbol_list(struct capn_segment *s, int len) {
	SilSymbol_list p;
	p.p = capn_new_list(s, len, 8, 3);
	return p;
}
void read_SilSymbol(struct SilSymbol *s capnp_unused, SilSymbol_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->name = capn_get_text(p.p, 0, capn_val0);
	s->signature = capn_get_text(p.p, 1, capn_val0);
	s->callconv = capn_get_text(p.p, 2, capn_val0);
	s->bits = capn_read32(p.p, 0);
}
void write_SilSymbol(const struct SilSymbol *s capnp_unused, SilSymbol_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->name);
	capn_set_text(p.p, 1, s->signature);
	capn_set_text(p.p, 2, s->callconv);
	capn_write32(p.p, 0, s->bits);
}
void get_SilSymbol(struct SilSymbol *s, SilSymbol_list l, int i) {
	SilSymbol_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilSymbol(s, p);
}
void set_SilSymbol(const struct SilSymbol *s, SilSymbol_list l, int i) {
	SilSymbol_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilSymbol(s, p);
}

capn_text SilSymbol_get_name(SilSymbol_ptr p)
{
	capn_text name;
	name = capn_get_text(p.p, 0, capn_val0);
	return name;
}

capn_text SilSymbol_get_signature(SilSymbol_ptr p)
{
	capn_text signature;
	signature = capn_get_text(p.p, 1, capn_val0);
	return signature;
}

capn_text SilSymbol_get_callconv(SilSymbol_ptr p)
{
	capn_text callconv;
	callconv = capn_get_text(p.p, 2, capn_val0);
	return callconv;
}

uint32_t SilSymbol_get_bits(SilSymbol_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 0);
	return bits;
}

void SilSymbol_set_name(SilSymbol_ptr p, capn_text name)
{
	capn_set_text(p.p, 0, name);
}

void SilSymbol_set_signature(SilSymbol_ptr p, capn_text signature)
{
	capn_set_text(p.p, 1, signature);
}

void SilSymbol_set_callconv(SilSymbol_ptr p, capn_text callconv)
{
	capn_set_text(p.p, 2, callconv);
}

void SilSymbol_set_bits(SilSymbol_ptr p, uint32_t bits)
{
	capn_write32(p.p, 0, bits);
}

SilFunctionBundle_ptr new_SilFunctionBundle(struct capn_segment *s) {
	SilFunctionBundle_ptr p;
	p.p = capn_new_struct(s, 40, 6);
	return p;
}
SilFunctionBundle_list new_SilFunctionBundle_list(struct capn_segment *s, int len) {
	SilFunctionBundle_list p;
	p.p = capn_new_list(s, len, 40, 6);
	return p;
}
void read_SilFunctionBundle(struct SilFunctionBundle *s capnp_unused, SilFunctionBundle_ptr p) {
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
	s->name = capn_get_text(p.p, 3, capn_val0);
	s->signature = capn_get_text(p.p, 4, capn_val0);
	s->callconv = capn_get_text(p.p, 5, capn_val0);
	s->sectionOffset = capn_read64(p.p, 32);
}
void write_SilFunctionBundle(const struct SilFunctionBundle *s capnp_unused, SilFunctionBundle_ptr p) {
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
	capn_set_text(p.p, 3, s->name);
	capn_set_text(p.p, 4, s->signature);
	capn_set_text(p.p, 5, s->callconv);
	capn_write64(p.p, 32, s->sectionOffset);
}
void get_SilFunctionBundle(struct SilFunctionBundle *s, SilFunctionBundle_list l, int i) {
	SilFunctionBundle_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilFunctionBundle(s, p);
}
void set_SilFunctionBundle(const struct SilFunctionBundle *s, SilFunctionBundle_list l, int i) {
	SilFunctionBundle_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilFunctionBundle(s, p);
}

uint64_t SilFunctionBundle_get_addr(SilFunctionBundle_ptr p)
{
	uint64_t addr;
	addr = capn_read64(p.p, 0);
	return addr;
}

uint32_t SilFunctionBundle_get_size(SilFunctionBundle_ptr p)
{
	uint32_t size;
	size = capn_read32(p.p, 8);
	return size;
}

uint32_t SilFunctionBundle_get_bits(SilFunctionBundle_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 12);
	return bits;
}

capn_text SilFunctionBundle_get_arch(SilFunctionBundle_ptr p)
{
	capn_text arch;
	arch = capn_get_text(p.p, 0, capn_val0);
	return arch;
}

uint32_t SilFunctionBundle_get_length(SilFunctionBundle_ptr p)
{
	uint32_t length;
	length = capn_read32(p.p, 16);
	return length;
}

capn_data SilFunctionBundle_get_digest(SilFunctionBundle_ptr p)
{
	capn_data digest;
	digest = capn_get_data(p.p, 1);
	return digest;
}

capn_text SilFunctionBundle_get_sectionName(SilFunctionBundle_ptr p)
{
	capn_text sectionName;
	sectionName = capn_get_text(p.p, 2, capn_val0);
	return sectionName;
}

uint64_t SilFunctionBundle_get_sectionPaddr(SilFunctionBundle_ptr p)
{
	uint64_t sectionPaddr;
	sectionPaddr = capn_read64(p.p, 24);
	return sectionPaddr;
}

capn_text SilFunctionBundle_get_name(SilFunctionBundle_ptr p)
{
	capn_text name;
	name = capn_get_text(p.p, 3, capn_val0);
	return name;
}

capn_text SilFunctionBundle_get_signature(SilFunctionBundle_ptr p)
{
	capn_text signature;
	signature = capn_get_text(p.p, 4, capn_val0);
	return signature;
}

capn_text SilFunctionBundle_get_callconv(SilFunctionBundle_ptr p)
{
	capn_text callconv;
	callconv = capn_get_text(p.p, 5, capn_val0);
	return callconv;
}

uint64_t SilFunctionBundle_get_sectionOffset(SilFunctionBundle_ptr p)
{
	uint64_t sectionOffset;
	sectionOffset = capn_read64(p.p, 32);
	return sectionOffset;
}

void SilFunctionBundle_set_addr(SilFunctionBundle_ptr p, uint64_t addr)
{
	capn_write64(p.p, 0, addr);
}

void SilFunctionBundle_set_size(SilFunctionBundle_ptr p, uint32_t size)
{
	capn_write32(p.p, 8, size);
}

void SilFunctionBundle_set_bits(SilFunctionBundle_ptr p, uint32_t bits)
{
	capn_write32(p.p, 12, bits);
}

void SilFunctionBundle_set_arch(SilFunctionBundle_ptr p, capn_text arch)
{
	capn_set_text(p.p, 0, arch);
}

void SilFunctionBundle_set_length(SilFunctionBundle_ptr p, uint32_t length)
{
	capn_write32(p.p, 16, length);
}

void SilFunctionBundle_set_digest(SilFunctionBundle_ptr p, capn_data digest)
{
	capn_setp(p.p, 1, digest.p);
}

void SilFunctionBundle_set_sectionName(SilFunctionBundle_ptr p, capn_text sectionName)
{
	capn_set_text(p.p, 2, sectionName);
}

void SilFunctionBundle_set_sectionPaddr(SilFunctionBundle_ptr p, uint64_t sectionPaddr)
{
	capn_write64(p.p, 24, sectionPaddr);
}

void SilFunctionBundle_set_name(SilFunctionBundle_ptr p, capn_text name)
{
	capn_set_text(p.p, 3, name);
}

void SilFunctionBundle_set_signature(SilFunctionBundle_ptr p, capn_text signature)
{
	capn_set_text(p.p, 4, signature);
}

void SilFunctionBundle_set_callconv(SilFunctionBundle_ptr p, capn_text callconv)
{
	capn_set_text(p.p, 5, callconv);
}

void SilFunctionBundle_set_sectionOffset(SilFunctionBundle_ptr p, uint64_t sectionOffset)
{
	capn_write64(p.p, 32, sectionOffset);
}

SilProgramBundle_ptr new_SilProgramBundle(struct capn_segment *s) {
	SilProgramBundle_ptr p;
	p.p = capn_new_struct(s, 8, 6);
	return p;
}
SilProgramBundle_list new_SilProgramBundle_list(struct capn_segment *s, int len) {
	SilProgramBundle_list p;
	p.p = capn_new_list(s, len, 8, 6);
	return p;
}
void read_SilProgramBundle(struct SilProgramBundle *s capnp_unused, SilProgramBundle_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->binaryType = capn_get_text(p.p, 0, capn_val0);
	s->os = capn_get_text(p.p, 1, capn_val0);
	s->arch = capn_get_text(p.p, 2, capn_val0);
	s->bits = capn_read32(p.p, 0);
	s->binaryId = capn_get_text(p.p, 3, capn_val0);
	s->sections.p = capn_getp(p.p, 4, 0);
	s->functions.p = capn_getp(p.p, 5, 0);
}
void write_SilProgramBundle(const struct SilProgramBundle *s capnp_unused, SilProgramBundle_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->binaryType);
	capn_set_text(p.p, 1, s->os);
	capn_set_text(p.p, 2, s->arch);
	capn_write32(p.p, 0, s->bits);
	capn_set_text(p.p, 3, s->binaryId);
	capn_setp(p.p, 4, s->sections.p);
	capn_setp(p.p, 5, s->functions.p);
}
void get_SilProgramBundle(struct SilProgramBundle *s, SilProgramBundle_list l, int i) {
	SilProgramBundle_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilProgramBundle(s, p);
}
void set_SilProgramBundle(const struct SilProgramBundle *s, SilProgramBundle_list l, int i) {
	SilProgramBundle_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilProgramBundle(s, p);
}

capn_text SilProgramBundle_get_binaryType(SilProgramBundle_ptr p)
{
	capn_text binaryType;
	binaryType = capn_get_text(p.p, 0, capn_val0);
	return binaryType;
}

capn_text SilProgramBundle_get_os(SilProgramBundle_ptr p)
{
	capn_text os;
	os = capn_get_text(p.p, 1, capn_val0);
	return os;
}

capn_text SilProgramBundle_get_arch(SilProgramBundle_ptr p)
{
	capn_text arch;
	arch = capn_get_text(p.p, 2, capn_val0);
	return arch;
}

uint32_t SilProgramBundle_get_bits(SilProgramBundle_ptr p)
{
	uint32_t bits;
	bits = capn_read32(p.p, 0);
	return bits;
}

capn_text SilProgramBundle_get_binaryId(SilProgramBundle_ptr p)
{
	capn_text binaryId;
	binaryId = capn_get_text(p.p, 3, capn_val0);
	return binaryId;
}

SilSectionHash_list SilProgramBundle_get_sections(SilProgramBundle_ptr p)
{
	SilSectionHash_list sections;
	sections.p = capn_getp(p.p, 4, 0);
	return sections;
}

SilFunctionBundle_list SilProgramBundle_get_functions(SilProgramBundle_ptr p)
{
	SilFunctionBundle_list functions;
	functions.p = capn_getp(p.p, 5, 0);
	return functions;
}

void SilProgramBundle_set_binaryType(SilProgramBundle_ptr p, capn_text binaryType)
{
	capn_set_text(p.p, 0, binaryType);
}

void SilProgramBundle_set_os(SilProgramBundle_ptr p, capn_text os)
{
	capn_set_text(p.p, 1, os);
}

void SilProgramBundle_set_arch(SilProgramBundle_ptr p, capn_text arch)
{
	capn_set_text(p.p, 2, arch);
}

void SilProgramBundle_set_bits(SilProgramBundle_ptr p, uint32_t bits)
{
	capn_write32(p.p, 0, bits);
}

void SilProgramBundle_set_binaryId(SilProgramBundle_ptr p, capn_text binaryId)
{
	capn_set_text(p.p, 3, binaryId);
}

void SilProgramBundle_set_sections(SilProgramBundle_ptr p, SilSectionHash_list sections)
{
	capn_setp(p.p, 4, sections.p);
}

void SilProgramBundle_set_functions(SilProgramBundle_ptr p, SilFunctionBundle_list functions)
{
	capn_setp(p.p, 5, functions.p);
}

SilPing_ptr new_SilPing(struct capn_segment *s) {
	SilPing_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
SilPing_list new_SilPing_list(struct capn_segment *s, int len) {
	SilPing_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_SilPing(struct SilPing *s capnp_unused, SilPing_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->reserved = (capn_read8(p.p, 0) & 1) != 0;
}
void write_SilPing(const struct SilPing *s capnp_unused, SilPing_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write1(p.p, 0, s->reserved != 0);
}
void get_SilPing(struct SilPing *s, SilPing_list l, int i) {
	SilPing_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilPing(s, p);
}
void set_SilPing(const struct SilPing *s, SilPing_list l, int i) {
	SilPing_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilPing(s, p);
}

unsigned SilPing_get_reserved(SilPing_ptr p)
{
	unsigned reserved;
	reserved = (capn_read8(p.p, 0) & 1) != 0;
	return reserved;
}

void SilPing_set_reserved(SilPing_ptr p, unsigned reserved)
{
	capn_write1(p.p, 0, reserved != 0);
}

SilResolveProgram_ptr new_SilResolveProgram(struct capn_segment *s) {
	SilResolveProgram_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
SilResolveProgram_list new_SilResolveProgram_list(struct capn_segment *s, int len) {
	SilResolveProgram_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_SilResolveProgram(struct SilResolveProgram *s capnp_unused, SilResolveProgram_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->program.p = capn_getp(p.p, 0, 0);
}
void write_SilResolveProgram(const struct SilResolveProgram *s capnp_unused, SilResolveProgram_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->program.p);
}
void get_SilResolveProgram(struct SilResolveProgram *s, SilResolveProgram_list l, int i) {
	SilResolveProgram_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilResolveProgram(s, p);
}
void set_SilResolveProgram(const struct SilResolveProgram *s, SilResolveProgram_list l, int i) {
	SilResolveProgram_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilResolveProgram(s, p);
}

SilProgramBundle_ptr SilResolveProgram_get_program(SilResolveProgram_ptr p)
{
	SilProgramBundle_ptr program;
	program.p = capn_getp(p.p, 0, 0);
	return program;
}

void SilResolveProgram_set_program(SilResolveProgram_ptr p, SilProgramBundle_ptr program)
{
	capn_setp(p.p, 0, program.p);
}

SilShareProgram_ptr new_SilShareProgram(struct capn_segment *s) {
	SilShareProgram_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
SilShareProgram_list new_SilShareProgram_list(struct capn_segment *s, int len) {
	SilShareProgram_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_SilShareProgram(struct SilShareProgram *s capnp_unused, SilShareProgram_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->program.p = capn_getp(p.p, 0, 0);
}
void write_SilShareProgram(const struct SilShareProgram *s capnp_unused, SilShareProgram_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->program.p);
}
void get_SilShareProgram(struct SilShareProgram *s, SilShareProgram_list l, int i) {
	SilShareProgram_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilShareProgram(s, p);
}
void set_SilShareProgram(const struct SilShareProgram *s, SilShareProgram_list l, int i) {
	SilShareProgram_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilShareProgram(s, p);
}

SilProgramBundle_ptr SilShareProgram_get_program(SilShareProgram_ptr p)
{
	SilProgramBundle_ptr program;
	program.p = capn_getp(p.p, 0, 0);
	return program;
}

void SilShareProgram_set_program(SilShareProgram_ptr p, SilProgramBundle_ptr program)
{
	capn_setp(p.p, 0, program.p);
}

SilRequest_ptr new_SilRequest(struct capn_segment *s) {
	SilRequest_ptr p;
	p.p = capn_new_struct(s, 8, 2);
	return p;
}
SilRequest_list new_SilRequest_list(struct capn_segment *s, int len) {
	SilRequest_list p;
	p.p = capn_new_list(s, len, 8, 2);
	return p;
}
void read_SilRequest(struct SilRequest *s capnp_unused, SilRequest_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->psk = capn_get_text(p.p, 0, capn_val0);
	s->version = capn_read32(p.p, 0);
	s->route = (enum SilRoute)(int) capn_read16(p.p, 4);
	s->which = (enum SilRequest_which)(int) capn_read16(p.p, 6);
	switch (s->which) {
	case SilRequest_ping:
	case SilRequest_resolveProgram:
	case SilRequest_shareProgram:
		s->shareProgram.p = capn_getp(p.p, 1, 0);
		break;
	default:
		break;
	}
}
void write_SilRequest(const struct SilRequest *s capnp_unused, SilRequest_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->psk);
	capn_write32(p.p, 0, s->version);
	capn_write16(p.p, 4, (uint16_t) (s->route));
	capn_write16(p.p, 6, s->which);
	switch (s->which) {
	case SilRequest_ping:
	case SilRequest_resolveProgram:
	case SilRequest_shareProgram:
		capn_setp(p.p, 1, s->shareProgram.p);
		break;
	default:
		break;
	}
}
void get_SilRequest(struct SilRequest *s, SilRequest_list l, int i) {
	SilRequest_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilRequest(s, p);
}
void set_SilRequest(const struct SilRequest *s, SilRequest_list l, int i) {
	SilRequest_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilRequest(s, p);
}

capn_text SilRequest_get_psk(SilRequest_ptr p)
{
	capn_text psk;
	psk = capn_get_text(p.p, 0, capn_val0);
	return psk;
}

uint32_t SilRequest_get_version(SilRequest_ptr p)
{
	uint32_t version;
	version = capn_read32(p.p, 0);
	return version;
}

enum SilRoute SilRequest_get_route(SilRequest_ptr p)
{
	enum SilRoute route;
	route = (enum SilRoute)(int) capn_read16(p.p, 4);
	return route;
}

void SilRequest_set_psk(SilRequest_ptr p, capn_text psk)
{
	capn_set_text(p.p, 0, psk);
}

void SilRequest_set_version(SilRequest_ptr p, uint32_t version)
{
	capn_write32(p.p, 0, version);
}

void SilRequest_set_route(SilRequest_ptr p, enum SilRoute route)
{
	capn_write16(p.p, 4, (uint16_t) (route));
}

SilMessage_ptr new_SilMessage(struct capn_segment *s) {
	SilMessage_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
SilMessage_list new_SilMessage_list(struct capn_segment *s, int len) {
	SilMessage_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_SilMessage(struct SilMessage *s capnp_unused, SilMessage_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->text = capn_get_text(p.p, 0, capn_val0);
}
void write_SilMessage(const struct SilMessage *s capnp_unused, SilMessage_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->text);
}
void get_SilMessage(struct SilMessage *s, SilMessage_list l, int i) {
	SilMessage_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilMessage(s, p);
}
void set_SilMessage(const struct SilMessage *s, SilMessage_list l, int i) {
	SilMessage_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilMessage(s, p);
}

capn_text SilMessage_get_text(SilMessage_ptr p)
{
	capn_text text;
	text = capn_get_text(p.p, 0, capn_val0);
	return text;
}

void SilMessage_set_text(SilMessage_ptr p, capn_text text)
{
	capn_set_text(p.p, 0, text);
}

SilServerInfo_ptr new_SilServerInfo(struct capn_segment *s) {
	SilServerInfo_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
SilServerInfo_list new_SilServerInfo_list(struct capn_segment *s, int len) {
	SilServerInfo_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_SilServerInfo(struct SilServerInfo *s capnp_unused, SilServerInfo_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->supportedCodecs.p = capn_getp(p.p, 0, 0);
	s->version = capn_read32(p.p, 0);
	s->tlsRequired = (capn_read8(p.p, 4) & 1) != 0;
}
void write_SilServerInfo(const struct SilServerInfo *s capnp_unused, SilServerInfo_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->supportedCodecs.p);
	capn_write32(p.p, 0, s->version);
	capn_write1(p.p, 32, s->tlsRequired != 0);
}
void get_SilServerInfo(struct SilServerInfo *s, SilServerInfo_list l, int i) {
	SilServerInfo_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilServerInfo(s, p);
}
void set_SilServerInfo(const struct SilServerInfo *s, SilServerInfo_list l, int i) {
	SilServerInfo_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilServerInfo(s, p);
}

capn_list16 SilServerInfo_get_supportedCodecs(SilServerInfo_ptr p)
{
	capn_list16 supportedCodecs;
	supportedCodecs.p = capn_getp(p.p, 0, 0);
	return supportedCodecs;
}

uint32_t SilServerInfo_get_version(SilServerInfo_ptr p)
{
	uint32_t version;
	version = capn_read32(p.p, 0);
	return version;
}

unsigned SilServerInfo_get_tlsRequired(SilServerInfo_ptr p)
{
	unsigned tlsRequired;
	tlsRequired = (capn_read8(p.p, 4) & 1) != 0;
	return tlsRequired;
}

void SilServerInfo_set_supportedCodecs(SilServerInfo_ptr p, capn_list16 supportedCodecs)
{
	capn_setp(p.p, 0, supportedCodecs.p);
}

void SilServerInfo_set_version(SilServerInfo_ptr p, uint32_t version)
{
	capn_write32(p.p, 0, version);
}

void SilServerInfo_set_tlsRequired(SilServerInfo_ptr p, unsigned tlsRequired)
{
	capn_write1(p.p, 32, tlsRequired != 0);
}

SilSymbolMatch_ptr new_SilSymbolMatch(struct capn_segment *s) {
	SilSymbolMatch_ptr p;
	p.p = capn_new_struct(s, 24, 3);
	return p;
}
SilSymbolMatch_list new_SilSymbolMatch_list(struct capn_segment *s, int len) {
	SilSymbolMatch_list p;
	p.p = capn_new_list(s, len, 24, 3);
	return p;
}
void read_SilSymbolMatch(struct SilSymbolMatch *s capnp_unused, SilSymbolMatch_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->addr = capn_read64(p.p, 0);
	s->symbol.p = capn_getp(p.p, 0, 0);
	s->exact = (capn_read8(p.p, 8) & 1) != 0;
	s->matchedBinaryId = capn_get_text(p.p, 1, capn_val0);
	s->matchedBy = capn_get_text(p.p, 2, capn_val0);
	s->offset = capn_read64(p.p, 16);
	s->size = capn_read32(p.p, 12);
}
void write_SilSymbolMatch(const struct SilSymbolMatch *s capnp_unused, SilSymbolMatch_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write64(p.p, 0, s->addr);
	capn_setp(p.p, 0, s->symbol.p);
	capn_write1(p.p, 64, s->exact != 0);
	capn_set_text(p.p, 1, s->matchedBinaryId);
	capn_set_text(p.p, 2, s->matchedBy);
	capn_write64(p.p, 16, s->offset);
	capn_write32(p.p, 12, s->size);
}
void get_SilSymbolMatch(struct SilSymbolMatch *s, SilSymbolMatch_list l, int i) {
	SilSymbolMatch_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilSymbolMatch(s, p);
}
void set_SilSymbolMatch(const struct SilSymbolMatch *s, SilSymbolMatch_list l, int i) {
	SilSymbolMatch_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilSymbolMatch(s, p);
}

uint64_t SilSymbolMatch_get_addr(SilSymbolMatch_ptr p)
{
	uint64_t addr;
	addr = capn_read64(p.p, 0);
	return addr;
}

SilSymbol_ptr SilSymbolMatch_get_symbol(SilSymbolMatch_ptr p)
{
	SilSymbol_ptr symbol;
	symbol.p = capn_getp(p.p, 0, 0);
	return symbol;
}

unsigned SilSymbolMatch_get_exact(SilSymbolMatch_ptr p)
{
	unsigned exact;
	exact = (capn_read8(p.p, 8) & 1) != 0;
	return exact;
}

capn_text SilSymbolMatch_get_matchedBinaryId(SilSymbolMatch_ptr p)
{
	capn_text matchedBinaryId;
	matchedBinaryId = capn_get_text(p.p, 1, capn_val0);
	return matchedBinaryId;
}

capn_text SilSymbolMatch_get_matchedBy(SilSymbolMatch_ptr p)
{
	capn_text matchedBy;
	matchedBy = capn_get_text(p.p, 2, capn_val0);
	return matchedBy;
}

uint64_t SilSymbolMatch_get_offset(SilSymbolMatch_ptr p)
{
	uint64_t offset;
	offset = capn_read64(p.p, 16);
	return offset;
}

uint32_t SilSymbolMatch_get_size(SilSymbolMatch_ptr p)
{
	uint32_t size;
	size = capn_read32(p.p, 12);
	return size;
}

void SilSymbolMatch_set_addr(SilSymbolMatch_ptr p, uint64_t addr)
{
	capn_write64(p.p, 0, addr);
}

void SilSymbolMatch_set_symbol(SilSymbolMatch_ptr p, SilSymbol_ptr symbol)
{
	capn_setp(p.p, 0, symbol.p);
}

void SilSymbolMatch_set_exact(SilSymbolMatch_ptr p, unsigned exact)
{
	capn_write1(p.p, 64, exact != 0);
}

void SilSymbolMatch_set_matchedBinaryId(SilSymbolMatch_ptr p, capn_text matchedBinaryId)
{
	capn_set_text(p.p, 1, matchedBinaryId);
}

void SilSymbolMatch_set_matchedBy(SilSymbolMatch_ptr p, capn_text matchedBy)
{
	capn_set_text(p.p, 2, matchedBy);
}

void SilSymbolMatch_set_offset(SilSymbolMatch_ptr p, uint64_t offset)
{
	capn_write64(p.p, 16, offset);
}

void SilSymbolMatch_set_size(SilSymbolMatch_ptr p, uint32_t size)
{
	capn_write32(p.p, 12, size);
}

SilResolveResult_ptr new_SilResolveResult(struct capn_segment *s) {
	SilResolveResult_ptr p;
	p.p = capn_new_struct(s, 0, 2);
	return p;
}
SilResolveResult_list new_SilResolveResult_list(struct capn_segment *s, int len) {
	SilResolveResult_list p;
	p.p = capn_new_list(s, len, 0, 2);
	return p;
}
void read_SilResolveResult(struct SilResolveResult *s capnp_unused, SilResolveResult_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->hints.p = capn_getp(p.p, 0, 0);
	s->symbols.p = capn_getp(p.p, 1, 0);
}
void write_SilResolveResult(const struct SilResolveResult *s capnp_unused, SilResolveResult_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_setp(p.p, 0, s->hints.p);
	capn_setp(p.p, 1, s->symbols.p);
}
void get_SilResolveResult(struct SilResolveResult *s, SilResolveResult_list l, int i) {
	SilResolveResult_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilResolveResult(s, p);
}
void set_SilResolveResult(const struct SilResolveResult *s, SilResolveResult_list l, int i) {
	SilResolveResult_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilResolveResult(s, p);
}

SilHint_list SilResolveResult_get_hints(SilResolveResult_ptr p)
{
	SilHint_list hints;
	hints.p = capn_getp(p.p, 0, 0);
	return hints;
}

SilSymbolMatch_list SilResolveResult_get_symbols(SilResolveResult_ptr p)
{
	SilSymbolMatch_list symbols;
	symbols.p = capn_getp(p.p, 1, 0);
	return symbols;
}

void SilResolveResult_set_hints(SilResolveResult_ptr p, SilHint_list hints)
{
	capn_setp(p.p, 0, hints.p);
}

void SilResolveResult_set_symbols(SilResolveResult_ptr p, SilSymbolMatch_list symbols)
{
	capn_setp(p.p, 1, symbols.p);
}

SilShareResult_ptr new_SilShareResult(struct capn_segment *s) {
	SilShareResult_ptr p;
	p.p = capn_new_struct(s, 0, 1);
	return p;
}
SilShareResult_list new_SilShareResult_list(struct capn_segment *s, int len) {
	SilShareResult_list p;
	p.p = capn_new_list(s, len, 0, 1);
	return p;
}
void read_SilShareResult(struct SilShareResult *s capnp_unused, SilShareResult_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->binaryId = capn_get_text(p.p, 0, capn_val0);
}
void write_SilShareResult(const struct SilShareResult *s capnp_unused, SilShareResult_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_set_text(p.p, 0, s->binaryId);
}
void get_SilShareResult(struct SilShareResult *s, SilShareResult_list l, int i) {
	SilShareResult_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilShareResult(s, p);
}
void set_SilShareResult(const struct SilShareResult *s, SilShareResult_list l, int i) {
	SilShareResult_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilShareResult(s, p);
}

capn_text SilShareResult_get_binaryId(SilShareResult_ptr p)
{
	capn_text binaryId;
	binaryId = capn_get_text(p.p, 0, capn_val0);
	return binaryId;
}

void SilShareResult_set_binaryId(SilShareResult_ptr p, capn_text binaryId)
{
	capn_set_text(p.p, 0, binaryId);
}

SilResponse_ptr new_SilResponse(struct capn_segment *s) {
	SilResponse_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
SilResponse_list new_SilResponse_list(struct capn_segment *s, int len) {
	SilResponse_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_SilResponse(struct SilResponse *s capnp_unused, SilResponse_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->status = (enum SilStatus)(int) capn_read16(p.p, 0);
	s->which = (enum SilResponse_which)(int) capn_read16(p.p, 2);
	switch (s->which) {
	case SilResponse_message:
	case SilResponse_serverInfo:
	case SilResponse_resolveResult:
	case SilResponse_shareResult:
		s->shareResult.p = capn_getp(p.p, 0, 0);
		break;
	default:
		break;
	}
}
void write_SilResponse(const struct SilResponse *s capnp_unused, SilResponse_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write16(p.p, 0, (uint16_t) (s->status));
	capn_write16(p.p, 2, s->which);
	switch (s->which) {
	case SilResponse_message:
	case SilResponse_serverInfo:
	case SilResponse_resolveResult:
	case SilResponse_shareResult:
		capn_setp(p.p, 0, s->shareResult.p);
		break;
	default:
		break;
	}
}
void get_SilResponse(struct SilResponse *s, SilResponse_list l, int i) {
	SilResponse_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_SilResponse(s, p);
}
void set_SilResponse(const struct SilResponse *s, SilResponse_list l, int i) {
	SilResponse_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_SilResponse(s, p);
}

enum SilStatus SilResponse_get_status(SilResponse_ptr p)
{
	enum SilStatus status;
	status = (enum SilStatus)(int) capn_read16(p.p, 0);
	return status;
}

void SilResponse_set_status(SilResponse_ptr p, enum SilStatus status)
{
	capn_write16(p.p, 0, (uint16_t) (status));
}
