
test_driver = executable('test_driver', 'driver.c',
                         dependencies: libx86decode,
                         c_args: ['-D_GNU_SOURCE'])
test_args = [files('test.py'), test_driver, archmode]


## Test cases

testcases = [
  ['enter', 'decode-enter.sh'],
  ['imul', 'decode-imul.sh'],
  ['inc', 'decode-inc.sh'],
  ['movsx', 'decode-movsx.sh'],
  ['ret', 'decode-ret.sh'],

  ['sse-shufpd', 'decode-sse-shufpd.sh'],
  ['sse-movq', 'decode-sse-movq.sh'],
]

foreach case : testcases
  test(case[0], python3, args: test_args + files(case[1]))
endforeach


## Benchmarks
#
# Note that we don't use meson's benchmark function here, because it doesn't
# give us the output we need by default.

benchmarks = [
  'benchmarks.txt',
]

run_target('benchmark_decode',
           command: [python3, test_args, '--benchmark', files(benchmarks)])
