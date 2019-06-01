import argparse

from apkid.apkid import Scanner, Options
from . import __version__


def get_parser():
    formatter = lambda prog: argparse.HelpFormatter(prog, max_help_position=50, width=100)

    parser = argparse.ArgumentParser(
        description=f"APKiD - Android Application Identifier v{__version__}",
        formatter_class=formatter
    )
    parser.add_argument('input', metavar='FILE', type=str, nargs='*',
                        help="apk, dex, or directory")
    parser.add_argument('-j', '--json', action='store_true',
                        help="output scan results in JSON format", )
    parser.add_argument('-t', '--timeout', type=int, default=30,
                        help="Yara scan timeout (in seconds)")
    parser.add_argument('-o', '--output-dir', metavar='DIR', default=None,
                        help="write individual results here (implies --json)")
    parser.add_argument('-r', '--recursive', action='store_true', default=True,
                        help="recurse into subdirectories")
    parser.add_argument('--scan-depth', type=int, default=2,
                        help="how deep to go when scanning nested zips")
    parser.add_argument('--entry-max-scan-size', type=int, default=100 * 1024 * 1024,
                        help="max zip entry size to scan in bytes, 0 = no limit")
    parser.add_argument('--typing', choices=('magic', 'filename', 'none'), default='magic',
                        help="method to decide which files to scan")
    parser.add_argument('-v', '--verbose', action='store_true',
                        help="log debug messages")
    return parser


def build_options(args) -> Options:
    return Options(
        timeout=args.timeout,
        verbose=args.verbose,
        json=args.json,
        output_dir=args.output_dir,
        typing=args.typing,
        entry_max_scan_size=args.entry_max_scan_size,
        scan_depth=args.scan_depth,
        recursive=args.recursive
    )


def main():
    parser = get_parser()
    args = parser.parse_args()
    options = build_options(args)

    if not options.output.json:
        print(f"[+] APKiD {__version__} :: from RedNaga :: rednaga.io")

    rules = options.rules_manager.load()
    scanner = Scanner(rules, options)

    for input in args.input:
        scanner.scan(input)


if __name__ == '__main__':
    main()
