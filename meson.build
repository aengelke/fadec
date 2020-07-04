project('fadec', ['c'], default_options: ['warning_level=3', 'c_std=c99'])

python3 = find_program('python3')

if get_option('warning_level').to_int() >= 3
  add_project_arguments(['-Wmissing-field-initializers',
                         '-Wunused-parameter',
                         '-Wold-style-definition',
                         '-Wmissing-declarations',
                         '-Wmissing-prototypes',
                         '-Wmissing-noreturn',
                         '-Wshadow',
                         '-Wpointer-arith',
                         '-Wcast-align',
                         '-Wwrite-strings',
                         '-Winline',
                         '-Wformat',
                         '-Wformat-nonliteral',
                         '-Wformat-security',
                         '-Wswitch-default',
                         '-Winit-self',
                         '-Wnested-externs',
                         '-Wstrict-prototypes',
                         '-Wmissing-include-dirs',
                         '-Wundef',
                         '-Waggregate-return',
                         '-Wredundant-decls',
                         '-Wno-overlength-strings',
                         '-Wmissing-format-attribute'],
                        language: 'c')
endif

decode_32 = false
decode_64 = false

archmode = get_option('archmode')
if archmode == 'only32' or archmode == 'both'
  add_project_arguments(['-DARCH_386'], language: 'c')
  decode_32 = true
endif
if archmode == 'only64' or archmode == 'both'
  add_project_arguments(['-DARCH_X86_64'], language: 'c')
  decode_64 = true
endif

if not decode_32 and not decode_64
  error('no architecture mode')
endif

generate_args = []
if decode_32
  generate_args += ['--32']
endif
if decode_64
  generate_args += ['--64']
endif
instr_data = custom_target('tables',
                           command: [python3, '@INPUT0@', '@INPUT1@', '@OUTPUT@'] + generate_args,
                           input: files('parseinstrs.py', 'instrs.txt'),
                           output: [
                             'fadec-mnems.inc', 'fadec-table.inc'
                           ],
                           install: true,
                           install_dir: [get_option('includedir'), false])

libfadec = static_library('fadec', 'decode.c', 'format.c', instr_data,
                          install: true)
fadec = declare_dependency(link_with: libfadec,
                           include_directories: include_directories('.'),
                           sources: instr_data)

subdir('tests')

install_headers('fadec.h')

pkg = import('pkgconfig')
pkg.generate(libraries: libfadec,
             version: '0.1',
             name: 'fadec',
             filebase: 'fadec',
             description: 'Fast Decoder for x86-32 and x86-64')
