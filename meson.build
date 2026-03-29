project('rz_silhouette', 'c',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
    'warning_level=1',
  ]
)

fs = import('fs')
cc = meson.get_compiler('c')
windows_host = host_machine.system() == 'windows'

rizin_plugdir = get_option('rizin_plugdir')
rizin_root = get_option('rizin_root')
rz_silhouette_c_args = []

rz_core_dep = dependency('rz_core', required: false)
rz_core_from_metadata = rz_core_dep.found()
if not rz_core_dep.found()
  if rizin_root == ''
    error('Rizin dependency rz_core was not found. Install Rizin development files or pass -Drizin_root=<prefix>.')
  endif

  rz_incdir = join_paths(rizin_root, 'include', 'librz')
  rz_sdb_incdir = join_paths(rizin_root, 'include', 'librz', 'sdb')
  rz_libdir = join_paths(rizin_root, 'lib')
  if not fs.exists(join_paths(rz_incdir, 'rz_core.h'))
    error('Rizin headers were not found under ' + rz_incdir)
  endif

  rz_manual_lib_names = [
    'rz_core',
    'rz_lang',
    'rz_mark',
    'rz_debug',
    'rz_egg',
    'rz_sign',
    'rz_arch',
    'rz_bin',
    'rz_demangler',
    'rz_config',
    'rz_syscall',
    'rz_diff',
    'rz_type',
    'rz_search',
    'rz_io',
    'rz_socket',
    'rz_cons',
    'rz_magic',
    'rz_hash',
    'rz_crypto',
    'rz_flag',
    'rz_il',
    'rz_reg',
    'rz_util',
  ]

  rz_manual_deps = []
  foreach rz_lib_name : rz_manual_lib_names
    rz_manual_deps += cc.find_library(rz_lib_name, dirs: [rz_libdir], required: true)
  endforeach
  if windows_host
    rz_manual_deps += cc.find_library('ws2_32', required: true)
    rz_manual_deps += cc.find_library('wininet', required: true)
    rz_manual_deps += cc.find_library('psapi', required: true)
  endif

  rz_core_dep = declare_dependency(
    dependencies: rz_manual_deps,
    include_directories: include_directories(rz_incdir, rz_sdb_incdir),
  )
endif

if rizin_plugdir == ''
  if rz_core_from_metadata
    rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
  else
    rizin_plugdir = join_paths(rizin_root, 'lib', 'rizin', 'plugins')
  endif
endif

capnp_tool = find_program('capnp', required: true)
sys_capnp_c_opt = get_option('use_sys_capnp_c')
capnp_c_dep = disabler()
capnpc_c = disabler()
if sys_capnp_c_opt.enabled() or sys_capnp_c_opt.auto()
  capnp_c_dep = dependency('CapnC', method: 'cmake', required: false)
  if not capnp_c_dep.found()
    capnp_c_dep = cc.find_library('CapnC_Runtime', required: false)
  endif
  capnpc_c = find_program('capnpc-c', required: false)
endif
if sys_capnp_c_opt.enabled() and (not capnp_c_dep.found() or not capnpc_c.found())
  error('System CapnC runtime and capnpc-c tool were not found')
endif
if (sys_capnp_c_opt.auto() and (not capnp_c_dep.found() or not capnpc_c.found())) or sys_capnp_c_opt.disabled()
  capnp_c_proj = subproject('c-capnproto', default_options: ['default_library=static', 'enable_tests=false'])
  capnp_c_dep = capnp_c_proj.get_variable('libcapnp_dep')
  capnpc_c = capnp_c_proj.get_variable('capnpc_c')
endif

capnp_schema_dir = join_paths(meson.current_source_dir(), 'src')
capnp_generated = custom_target(
  'service-capnp-c',
  input: 'src/service.capnp',
  output: ['service.capnp.c', 'service.capnp.h'],
  command: [
    capnp_tool,
    'compile',
    '--src-prefix=' + capnp_schema_dir,
    '-I' + capnp_schema_dir,
    '-o',
    capnpc_c,
    '@INPUT@',
  ],
)

rz_silhouette_deps = [
  rz_core_dep,
  dependency('threads', required: true),
  capnp_c_dep,
]

rz_silhouette_incs = include_directories('.', 'src')
rz_silhouette_src = [
  'src' / 'sil_client.c',
  'src' / 'sil_capnp.c',
  'src' / 'sil_helpers.c',
  'src' / 'sil_plugin.c',
  'src' / 'sil_protocol.c',
  capnp_generated,
]

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

shared_library('rz_silhouette', rz_silhouette_src,
  c_args: rz_silhouette_c_args,
  dependencies: rz_silhouette_deps,
  implicit_include_directories: false,
  include_directories: rz_silhouette_incs,
  install: true,
  install_dir: rizin_plugdir,
)
