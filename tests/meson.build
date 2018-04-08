
sh = find_program('sh')

cases = [
  ['enter', 'decode-enter.sh'],
  ['imul', 'decode-imul.sh'],
  ['inc', 'decode-inc.sh'],
  ['movsx', 'decode-movsx.sh'],
  ['ret', 'decode-ret.sh'],

  ['sse-shufpd', 'decode-sse-shufpd.sh'],
  ['sse-movq', 'decode-sse-movq.sh'],
]

test_driver = executable('test_driver', 'driver.c',
                         dependencies: libx86decode,
                         c_args: ['-D_GNU_SOURCE'])
test_args = files('common.sh') + [test_driver.full_path(), '@0@'.format(pointer_size * 8)]

foreach case : cases
  test(case[0], sh, args: test_args + files(case[1]))
endforeach
