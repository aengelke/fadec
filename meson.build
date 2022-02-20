project('fadec', ['c'], default_options: ['warning_level=3', 'c_std=c11'],
        meson_version: '>=0.40')

python3 = find_program('python3')

# Check Python version
py_version_res = run_command(python3, ['--version'])
py_version = py_version_res.stdout().split(' ')[1]
if py_version_res.returncode() != 0 or not py_version.version_compare('>=3.6')
  error('Python 3.6 required, got @0@'.format(py_version))
endif

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
  foreach warning : extra_warnings
    if cc.has_argument(warning)
      add_project_arguments(warning, language: 'c')
    endif
  endforeach
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
