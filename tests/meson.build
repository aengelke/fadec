
decode_test = executable('test_decode', 'test_decode.c',
                         dependencies: fadec)
test('decode', decode_test)

encode_test = executable('test_encode', 'test_encode.c',
                         dependencies: fadec,
                         c_args: ['-D_GNU_SOURCE'])
test('encode', encode_test)
