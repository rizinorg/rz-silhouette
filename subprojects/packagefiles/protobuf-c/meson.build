project('protobuf-c',
  ['c'],
  version : '1.4.1',
  default_options : [
    'buildtype=release',
    'c_std=c99',
  ],
  meson_version : '>=0.55.0',
)

cc = meson.get_compiler('c')

possible_cc_flags = [
  '-Wchar-subscripts',
  '-Wdeclaration-after-statement',
  '-Werror=incompatible-pointer-types',
  '-Werror=int-conversion',
  '-Wformat-security',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wnull-dereference',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-prototypes',
  '-Wtype-limits',
]
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')

if target_machine.endian() == 'big'
  add_project_arguments('-DWORDS_BIGENDIAN=1', language: ['c'])
endif

protobuf_c_sym = 'protobuf-c' / 'libprotobuf-c.sym'
protobuf_c_sym_path = join_paths(meson.current_source_dir(), protobuf_c_sym)

protobuf_c_args = []

protobuf_c_src = [
  'protobuf-c' / 'protobuf-c.c',
]

protobuf_c_incs = [
  'protobuf-c',
]

protobuf_c_lib = static_library('libprotobuf-c', protobuf_c_src,
  c_args : protobuf_c_args,
  link_args : ['-Wl,--version-script=' + protobuf_c_sym_path],
  link_depends : protobuf_c_sym,
  implicit_include_directories: false,
  install: false,
  include_directories: include_directories(protobuf_c_incs)
)

protobuf_c_dep = declare_dependency(
  link_with: protobuf_c_lib,
  include_directories: include_directories(protobuf_c_incs),
)
