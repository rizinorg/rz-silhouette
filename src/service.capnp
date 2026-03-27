# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

using C = import "/c.capnp";
using Go = import "/go.capnp";

@0xa0f8f4ce58fdd4d6;

$C.fieldgetset;
$Go.package("servicecapnp");
$Go.import("rz-silhouette-server/servicecapnp");

enum CodecV2 {
  protobuf @0;
  capnp @1;
}

enum RouteV2 {
  ping @0;
  resolveProgram @1;
  shareProgram @2;
}

enum StatusV2 {
  internalError @0;
  clientBadPreSharedKey @1;
  clientNotAuthorized @2;
  versionMismatch @3;
  shareWasSuccessful @4;
  message @5;
  serverInfo @6;
  resolveResult @7;
  shareResult @8;
}

struct SectionHashV2 {
  size @0 :UInt32;
  paddr @1 :UInt64;
  digest @2 :Data;
  name @3 :Text;
}

struct HintV2 {
  bits @0 :UInt32;
  offset @1 :UInt64;
  confidence @2 :Float32;
  matchedBinaryId @3 :Text;
}

struct SymbolV2 {
  name @0 :Text;
  signature @1 :Text;
  callconv @2 :Text;
  bits @3 :UInt32;
}

struct FunctionBundleV2 {
  addr @0 :UInt64;
  size @1 :UInt32;
  bits @2 :UInt32;
  arch @3 :Text;
  length @4 :UInt32;
  digest @5 :Data;
  sectionName @6 :Text;
  sectionPaddr @7 :UInt64;
  loc @8 :UInt32;
  nos @9 :UInt32;
  pseudocode @10 :Text;
  calls @11 :List(UInt64);
  name @12 :Text;
  signature @13 :Text;
  callconv @14 :Text;
  pseudocodeSource @15 :Text;
  sectionOffset @16 :UInt64;
}

struct ProgramBundleV2 {
  binaryType @0 :Text;
  os @1 :Text;
  arch @2 :Text;
  bits @3 :UInt32;
  binaryId @4 :Text;
  sections @5 :List(SectionHashV2);
  functions @6 :List(FunctionBundleV2);
  topk @7 :UInt32;
}

struct PingV2 {
  reserved @0 :Bool;
}

struct ResolveProgramV2 {
  program @0 :ProgramBundleV2;
}

struct ShareProgramV2 {
  program @0 :ProgramBundleV2;
}

struct RequestV2 {
  psk @0 :Text;
  version @1 :UInt32;
  route @2 :RouteV2;

  union {
    ping @3 :PingV2;
    resolveProgram @4 :ResolveProgramV2;
    shareProgram @5 :ShareProgramV2;
  }
}

struct MessageV2 {
  text @0 :Text;
}

struct ServerInfoV2 {
  supportedCodecs @0 :List(CodecV2);
  minVersion @1 :UInt32;
  maxVersion @2 :UInt32;
  keenhashEnabled @3 :Bool;
  decompilerRequired @4 :Bool;
  modelVersion @5 :Text;
  indexVersion @6 :Text;
  tlsRequired @7 :Bool;
}

struct SymbolMatchV2 {
  addr @0 :UInt64;
  symbol @1 :SymbolV2;
  confidence @2 :Float32;
  exact @3 :Bool;
  matchedBinaryId @4 :Text;
  matchedBy @5 :Text;
  offset @6 :UInt64;
  size @7 :UInt32;
}

struct ResolveResultV2 {
  hints @0 :List(HintV2);
  symbols @1 :List(SymbolMatchV2);
  candidateBinaryIds @2 :List(Text);
  modelVersion @3 :Text;
  indexVersion @4 :Text;
}

struct ShareResultV2 {
  binaryId @0 :Text;
  ingestedFunctions @1 :UInt32;
  candidateCount @2 :UInt32;
  modelVersion @3 :Text;
  indexVersion @4 :Text;
}

struct ResponseV2 {
  status @0 :StatusV2;

  union {
    message @1 :MessageV2;
    serverInfo @2 :ServerInfoV2;
    resolveResult @3 :ResolveResultV2;
    shareResult @4 :ShareResultV2;
  }
}
