
driver=$1
bits=$2
failed=0
total=0

decode() {
    output=$($driver $1)
    result=$?
    total=$((total+1))
    if [ $result -ne 0 ] || [ "$output" != "$2" ]
    then
        failed=$((failed+1))
        echo "FAIL: decode $@"
        echo "======================================="
        echo "$output"
        echo "======================================="
    fi
}
decode32() { if [ $bits = 32 ]; then decode "$@"; fi }
decode64() { if [ $bits = 64 ]; then decode "$@"; fi }

. $3

if [ $failed -ne 0 ]
then
    echo "FAILED: ${failed}/${total} cases"
    exit 1
else
    echo "PASS: ${total} cases passed"
fi
