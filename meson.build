project('fadec', ['c'], default_options: ['warning_level=3', 'c_std=c99'],
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

instr_data = custom_target('tables',
                           command: [python3, '@INPUT0@', '@INPUT1@', '@OUTPUT@'] + generate_args,
                           input: files('parseinstrs.py', 'instrs.txt'),
                           output: [
                             'fadec-mnems.inc', 'fadec-table.inc',
                             'fadec-enc-mnems.inc', 'fadec-enc-cases.inc',
                           ],
                           install: true,
                           install_dir: [
                             get_option('includedir'), false,
                             get_option('includedir'), false,
                           ])

libfadec = static_library('fadec', 'decode.c', 'encode.c', 'format.c', instr_data,
                          install: true)
fadec = declare_dependency(link_with: libfadec,
                           include_directories: include_directories('.'),
                           sources: instr_data)

test('decode', executable('decode-test', 'decode-test.c', dependencies: fadec))
test('encode', executable('encode-test', 'encode-test.c', dependencies: fadec))

install_headers('fadec.h', 'fadec-enc.h')

pkg = import('pkgconfig')
pkg.generate(libraries: libfadec,
             version: '0.1',
             name: 'fadec',
             filebase: 'fadec',
             description: 'Fast Decoder for x86-32 and x86-64')
