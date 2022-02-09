import test_definitions as td
import ignition as ig
import sys

tests = {
    'empty.gmi':      td.exists,
    'does_not_exist.gmi': td.does_not_exist
}

def main():
    for route, func in tests.items():
        response = ig.request(f'//localhost:1966/{route}')
        passed, msg = func(response)
        if not passed:
            print(f'[{func.__name__}] failed ({route}): {msg}') 
            sys.exit(-1)
        else:
            print(f'{func.__name__} passed ({route})')

if __name__ == '__main__':
    main()
