project('rz_silhouette', 'c',
  meson_version: '>=0.55.0',
  default_options: [
    'buildtype=debugoptimized',
    'b_vscrt=from_buildtype',
    'warning_level=1',
  ]
)

cc = meson.get_compiler('c')
rz_core_dep = dependency('rz_core')


# handle yara library
sys_protobuf_c_opt = get_option('use_sys_protobuf_c')
protobuf_c_dep = disabler()
if sys_protobuf_c_opt.enabled() or sys_protobuf_c_opt.auto()
  protobuf_c_dep = dependency('libprotobuf-c', required: false)
  if not protobuf_c_dep.found()
    protobuf_c_dep = cc.find_library('libprotobuf-c', required: sys_protobuf_c_opt)
  endif
endif
if (sys_protobuf_c_opt.auto() and not protobuf_c_dep.found()) or sys_protobuf_c_opt.disabled()
  protobuf_c_proj = subproject('protobuf-c', default_options: ['default_library=static'])
  protobuf_c_dep = protobuf_c_proj.get_variable('protobuf_c_dep')
endif

rz_silhouette_deps = [
  rz_core_dep,
  dependency('threads', required: true),
  protobuf_c_dep,
]

rz_silhouette_incs = [
  'src',
]

rz_silhouette_src = [
  'src'/'sil_client.c',
  'src'/'sil_helpers.c',
  'src'/'sil_plugin.c',
  'src'/'sil_protocol.c',
  'src'/'service.pb-c.c',
]

rizin_plugdir = get_option('rizin_plugdir')
if rizin_plugdir == ''
  rizin_plugdir = rz_core_dep.get_variable(pkgconfig: 'plugindir', cmake: 'rz_core_PLUGINDIR')
endif

if cc.has_argument('-fPIC')
  add_project_arguments('-fPIC', language: ['c'])
endif

rz_silhouette_lib = shared_library('rz_silhouette', rz_silhouette_src,
  c_args : [],
  dependencies: rz_silhouette_deps,
  implicit_include_directories: false,
  install: true,
  install_dir: rizin_plugdir,
  include_directories: include_directories(rz_silhouette_incs)
)
