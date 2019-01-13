#!/usr/bin/python3

import argparse
import statistics
import subprocess
import sys

def run(args, code, expected):
    inner_reps = 10000000 if args.benchmark else 1
    outer_reps = 3 if args.benchmark else 1
    times = []
    for _ in range(outer_reps):
        output = subprocess.check_output([args.driver, code, str(inner_reps)],
                                         universal_newlines=True)
        instr, time = tuple(output.split("\n", 1))
        if instr != expected:
            raise Exception('wrong result, expected %r got %r (code %r)' %
                            (expected, instr, code))
        if args.benchmark:
            times.append(float(time.split()[0]) / inner_reps)

    if args.benchmark:
        mean = statistics.mean(times)
        stdev = statistics.stdev(times)
        print("{:53} {:6.3f} ns (std: {:6.3f} ns)".format(expected, mean, stdev))

    return times

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark", action="store_true")
    parser.add_argument("driver")
    parser.add_argument("archmode", choices=[32, 64], type=int)
    parser.add_argument("cases", nargs="+", type=argparse.FileType('r'))
    args = parser.parse_args()

    failed, total = 0, 0
    total_times = []

    for file in args.cases:
        cases = [tuple(ln.strip().split(maxsplit=2)) for ln in file.readlines()]
        for op, code, expected in cases:
            if op == "decode32" and args.archmode != 32: continue
            if op == "decode64" and args.archmode != 64: continue

            # Compatibility with old test system
            if expected[0] == '"' and expected[-1] == '"':
                expected = expected[1:-1]

            try:
                total += 1
                total_times += run(args, code, expected)
            except Exception as e:
                failed += 1
                print("FAILED: %s" % e)

    if failed:
        print("FAILED %d/%d tests" % (failed, total))
        sys.exit(1)
    else:
        print("PASSED %d tests" % total)
        if args.benchmark:
            mean = statistics.mean(total_times)
            stdev = statistics.stdev(total_times)
            print("Average: {:6.3f} ns (std: {:6.3f} ns)".format(mean, stdev))
