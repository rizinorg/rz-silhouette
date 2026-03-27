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
rz_silhouette_c_args = []
rizin_plugdir = get_option('rizin_plugdir')
rizin_root = get_option('rizin_root')
windows_host = host_machine.system() == 'windows'

rz_core_dep = dependency('rz_core', required: false)
rz_core_from_metadata = rz_core_dep.found()
if not rz_core_dep.found() and rizin_root != ''
  rz_incdir = join_paths(rizin_root, 'include', 'librz')
  rz_sdb_incdir = join_paths(rizin_root, 'include', 'librz', 'sdb')
  rz_libdir = join_paths(rizin_root, 'lib')
  if fs.exists(join_paths(rz_incdir, 'rz_core.h'))
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
endif
if not rz_core_dep.found()
  error('Rizin dependency rz_core was not found. Install Rizin development files or pass -Drizin_root=<prefix>.')
endif
if rizin_plugdir == ''
  if rz_core_from_metadata
    rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
  else
    rizin_plugdir = join_paths(rizin_root, 'lib', 'rizin', 'plugins')
  endif
endif

# handle protobuf-c
sys_protobuf_c_opt = get_option('use_sys_protobuf_c')
protobuf_c_dep = disabler()
protobuf_c_is_system = false
protobuf_c_runtime_dll = ''
if sys_protobuf_c_opt.enabled() or sys_protobuf_c_opt.auto()
  protobuf_c_dep = dependency('libprotobuf-c', required: false)
  if not protobuf_c_dep.found()
    protobuf_c_dep = dependency('protobuf-c', required: false)
  endif
  if not protobuf_c_dep.found()
    protobuf_c_dep = cc.find_library('libprotobuf-c', required: false)
  endif
  if not protobuf_c_dep.found()
    protobuf_c_dep = cc.find_library('protobuf-c', required: false)
  endif
  protobuf_c_is_system = protobuf_c_dep.found()
endif
if sys_protobuf_c_opt.enabled() and not protobuf_c_dep.found()
  error('System protobuf-c runtime not found')
endif
if (sys_protobuf_c_opt.auto() and not protobuf_c_dep.found()) or sys_protobuf_c_opt.disabled()
  protobuf_c_proj = subproject('protobuf-c', default_options: ['default_library=static'])
  protobuf_c_dep = protobuf_c_proj.get_variable('protobuf_c_dep')
  protobuf_c_is_system = false
endif
if windows_host and protobuf_c_is_system
  rz_silhouette_c_args += ['-DPROTOBUF_C_USE_SHARED_LIB']
endif

# handle capnp-c
sys_capnp_c_opt = get_option('use_sys_capnp_c')
capnp_c_dep = disabler()
if sys_capnp_c_opt.enabled() or sys_capnp_c_opt.auto()
  capnp_c_dep = dependency('CapnC', method: 'cmake', required: false)
  if not capnp_c_dep.found()
    capnp_c_dep = cc.find_library('CapnC_Runtime', required: false)
  endif
endif
if sys_capnp_c_opt.enabled() and not capnp_c_dep.found()
  error('System CapnC runtime not found')
endif
if (sys_capnp_c_opt.auto() and not capnp_c_dep.found()) or sys_capnp_c_opt.disabled()
  capnp_c_proj = subproject('c-capnproto', default_options: ['default_library=static', 'enable_tests=false'])
  capnp_c_dep = capnp_c_proj.get_variable('libcapnp_dep')
endif

rz_silhouette_deps = [
  rz_core_dep,
  dependency('threads', required: true),
  protobuf_c_dep,
  capnp_c_dep,
]

rz_silhouette_incs = [
  'src',
]

rz_silhouette_src = [
  'src'/'sil_client.c',
  'src'/'sil_capnp.c',
  'src'/'sil_helpers.c',
  'src'/'sil_plugin.c',
  'src'/'sil_protocol.c',
  'src'/'service.capnp.c',
  'src'/'service.pb-c.c',
]

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

rz_silhouette_lib = shared_library('rz_silhouette', rz_silhouette_src,
  c_args : rz_silhouette_c_args,
  dependencies: rz_silhouette_deps,
  implicit_include_directories: false,
  install: true,
  install_dir: rizin_plugdir,
  include_directories: include_directories(rz_silhouette_incs)
)

if protobuf_c_runtime_dll != ''
  configure_file(
    input: protobuf_c_runtime_dll,
    output: 'protobuf-c.dll',
    copy: true,
  )
endif
