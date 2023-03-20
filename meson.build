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

rz_silhouette_deps = [
  rz_core_dep,
  dependency('threads', required: true),
  dependency('libprotobuf-c', required: true),
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
