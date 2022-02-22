from statistics import mean
import test_definitions as td
import ignition as ig
import sys
import time

tests = {
    'empty.gmi':      td.exists,
    'does_not_exist.gmi': td.does_not_exist
}

def bench_route(route):
    bench_times = list()
    last_time = time.perf_counter_ns()
    for i in range(0, 100):
        response = ig.request(f'//localhost:1966/{route}')
        current_time = time.perf_counter_ns()
        bench_times.append(current_time - last_time)
        last_time = current_time
    return bench_times

def print_benchmarks(name, times: list[int]):
    first = times[0] / 1000000.0
    minimum = min(times) / 1000000.0
    maximum = max(times) / 1000000.0
    average = mean(times) / 1000000.0
    print(f'{name} - first: {first}ms | min: {minimum}ms | max: {maximum}ms | mean: {average}ms')

def run_benchmarks():
    print('Running benchmarks...')
    print_benchmarks('Script', bench_route('has_script.gmi'))
    print_benchmarks('Empty', bench_route('empty.gmi'))


def run_integration():
    print('Running integration tests...')
    for route, func in tests.items():
        response = ig.request(f'//localhost:1966/{route}')
        passed, msg = func(response)
        if not passed:
            print(f'[{func.__name__}] failed ({route}): {msg}') 
            sys.exit(-1)
        else:
            print(f'{func.__name__} passed ({route})')


def main():
    run_integration()
    run_benchmarks()

        
if __name__ == '__main__':
    main()
