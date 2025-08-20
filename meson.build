project('fadec', ['c'], default_options: ['warning_level=3', 'c_std=c11'],
        meson_version: '>=0.49')

python3 = find_program('python3')

# Check Python version
py_version_res = run_command(python3, ['--version'], check: true)
py_version = py_version_res.stdout().split(' ')[1]
if not py_version.version_compare('>=3.9')
  error('Python 3.9 required, got @0@'.format(py_version))
endif

has_cpp = add_languages('cpp', required: false)

cc = meson.get_compiler('c')
if cc.has_argument('-fstrict-aliasing')
  add_project_arguments('-fstrict-aliasing', language: 'c')
endif
if get_option('warning_level').to_int() >= 3
  extra_warnings = [
    '-Wmissing-prototypes', '-Wshadow',  '-Wwrite-strings', '-Wswitch-default',
    '-Winline', '-Wstrict-prototypes', '-Wundef',
    # We have strings longer than 4095 characters
    '-Wno-overlength-strings',
    # GCC 8 requires an extra option for strict cast alignment checks, Clang
    # always warns, even on architectures without alignment requirements.
    '-Wcast-align', '-Wcast-align=strict',
  ]
  add_project_arguments(cc.get_supported_arguments(extra_warnings), language: 'c')
endif
if cc.get_argument_syntax() == 'msvc'
  # Disable some warnings to align warnings with GCC and Clang:
  add_project_arguments('-D_CRT_SECURE_NO_WARNINGS',
                        '/wd4018', # - Signed/unsigned comparison
                        '/wd4146', # - Unary minus operator applied to unsigned
                                   #   type, result still unsigned
                        '/wd4244', # - Possible loss of data in conversion
                                   #   from integer type to smaller integer type
                        '/wd4245', # - Signed/unsigned assignment
                        '/wd4267', # - Possible loss of data in conversion
                                   #   from size_t to smaller type
                        '/wd4310', # - Possible loss of data in conversion
                                   #   of constant value to smaller type
                        language: 'c')
endif
if cc.get_id() == 'msvc' and has_cpp
  cxx = meson.get_compiler('cpp')
  if cxx.get_id() == 'msvc'
    # Enable standard conformant preprocessor
    add_project_arguments(cxx.get_supported_arguments(['-Zc:preprocessor']), language: 'cpp')
  endif
endif

sources = []
headers = []
components = []

if get_option('with_decode')
  components += 'decode'
  headers += files('fadec.h')
  sources += files('decode.c', 'format.c')
endif
if get_option('with_encode')
  components += 'encode'
  headers += files('fadec-enc.h')
  sources += files('encode.c')
endif
if get_option('with_encode2')
  components += 'encode2'
  headers += files('fadec-enc2.h')
  sources += files('encode2.c')
endif

generate_args = []
if get_option('archmode') != 'only64'
  generate_args += ['--32']
endif
if get_option('archmode') != 'only32'
  generate_args += ['--64']
endif
if get_option('with_undoc')
  generate_args += ['--with-undoc']
endif
if not meson.is_subproject()
  generate_args += ['--stats']
endif

tables = []
foreach component : components
  tables += custom_target('@0@_table'.format(component),
                          command: [python3, '@INPUT0@', component,
                                    '@INPUT1@', '@OUTPUT@'] + generate_args,
                          input: files('parseinstrs.py', 'instrs.txt'),
                          output: ['fadec-@0@-public.inc'.format(component),
                                   'fadec-@0@-private.inc'.format(component)],
                          install: true,
                          install_dir: [get_option('includedir'), false])
endforeach

libfadec = static_library('fadec', sources, tables, install: true)
fadec = declare_dependency(link_with: libfadec,
                           include_directories: include_directories('.'),
                           sources: tables)
install_headers(headers)

foreach component : components
  test(component, executable('@0@-test'.format(component),
                             '@0@-test.c'.format(component),
                             dependencies: fadec))
  if component == 'encode2' and has_cpp
    test(component + '-cpp', executable('@0@-test-cpp'.format(component),
                                        '@0@-test.cc'.format(component),
                                        dependencies: fadec))
  endif
endforeach

if meson.version().version_compare('>=0.54.0')
  meson.override_dependency('fadec', fadec)
endif

pkg = import('pkgconfig')
pkg.generate(libraries: libfadec,
             version: '0.1',
             name: 'fadec',
             filebase: 'fadec',
             description: 'Fast Decoder for x86-32 and x86-64')
