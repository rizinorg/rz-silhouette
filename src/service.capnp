# SPDX-FileCopyrightText: 2026 RizinOrg <info@rizin.re>
# SPDX-License-Identifier: LGPL-3.0-only

using C = import "capnp/c.capnp";
using Go = import "capnp/go.capnp";

@0xa0f8f4ce58fdd4d6;

$C.fieldgetset;
$Go.package("servicecapnp");
$Go.import("rz-silhouette-server/servicecapnp");

enum SilCodec {
  capnp @0;
}

enum SilRoute {
  ping @0;
  resolveProgram @1;
  shareProgram @2;
}

enum SilStatus {
  internalError @0;
  clientBadPreSharedKey @1;
  clientNotAuthorized @2;
  versionMismatch @3;
  message @4;
  serverInfo @5;
  resolveResult @6;
  shareResult @7;
}

struct SilSectionHash {
  size @0 :UInt32;
  paddr @1 :UInt64;
  digest @2 :Data;
  name @3 :Text;
}

struct SilHint {
  bits @0 :UInt32;
  offset @1 :UInt64;
}

struct SilSymbol {
  name @0 :Text;
  signature @1 :Text;
  callconv @2 :Text;
  bits @3 :UInt32;
}

struct SilFunctionBundle {
  addr @0 :UInt64;
  size @1 :UInt32;
  bits @2 :UInt32;
  arch @3 :Text;
  length @4 :UInt32;
  digest @5 :Data;
  sectionName @6 :Text;
  sectionPaddr @7 :UInt64;
  name @8 :Text;
  signature @9 :Text;
  callconv @10 :Text;
  sectionOffset @11 :UInt64;
}

struct SilProgramBundle {
  binaryType @0 :Text;
  os @1 :Text;
  arch @2 :Text;
  bits @3 :UInt32;
  binaryId @4 :Text;
  sections @5 :List(SilSectionHash);
  functions @6 :List(SilFunctionBundle);
}

struct SilPing {
  reserved @0 :Bool;
}

struct SilResolveProgram {
  program @0 :SilProgramBundle;
}

struct SilShareProgram {
  program @0 :SilProgramBundle;
}

struct SilRequest {
  psk @0 :Text;
  version @1 :UInt32;
  route @2 :SilRoute;

  union {
    ping @3 :SilPing;
    resolveProgram @4 :SilResolveProgram;
    shareProgram @5 :SilShareProgram;
  }
}

struct SilMessage {
  text @0 :Text;
}

struct SilServerInfo {
  supportedCodecs @0 :List(SilCodec);
  version @1 :UInt32;
  tlsRequired @2 :Bool;
}

struct SilSymbolMatch {
  addr @0 :UInt64;
  symbol @1 :SilSymbol;
  exact @2 :Bool;
  matchedBinaryId @3 :Text;
  matchedBy @4 :Text;
  offset @5 :UInt64;
  size @6 :UInt32;
}

struct SilResolveResult {
  hints @0 :List(SilHint);
  symbols @1 :List(SilSymbolMatch);
}

struct SilShareResult {
  binaryId @0 :Text;
}

struct SilResponse {
  status @0 :SilStatus;

  union {
    message @1 :SilMessage;
    serverInfo @2 :SilServerInfo;
    resolveResult @3 :SilResolveResult;
    shareResult @4 :SilShareResult;
  }
}
