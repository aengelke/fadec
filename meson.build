project('fadec', ['c'], default_options: ['warning_level=3', 'c_std=c99'])

python3 = find_program('python3')

if get_option('warning_level').to_int() >= 3
  add_project_arguments(['-Wmissing-prototypes',
                         '-Wshadow',
                         '-Wcast-align=strict',
                         '-Wwrite-strings',
                         '-Winline',
                         '-Wswitch-default',
                         '-Wstrict-prototypes',
                         '-Wundef',
                         '-Wno-overlength-strings'],
                        language: 'c')
endif

generate_args = []
if get_option('archmode') != 'only64'
  generate_args += ['--32']
endif
if get_option('archmode') != 'only32'
  generate_args += ['--64']
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

subdir('tests')

install_headers('fadec.h', 'fadec-enc.h')

pkg = import('pkgconfig')
pkg.generate(libraries: libfadec,
             version: '0.1',
             name: 'fadec',
             filebase: 'fadec',
             description: 'Fast Decoder for x86-32 and x86-64')
