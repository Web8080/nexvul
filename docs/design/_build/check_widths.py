"""Check that every fenced block preceded by <!-- cols:N --> fits in N columns.

Design tooling only. Usage: python3 -I check_widths.py <markdown file>
Width is measured with unicodedata east-asian width (wide chars count 2).
"""
import re
import sys
import unicodedata


def width(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def main(path: str) -> int:
    lines = open(path, encoding="utf-8").read().splitlines()
    want = None
    in_block = False
    errors = 0
    blocks = 0
    for n, line in enumerate(lines, 1):
        m = re.match(r"<!-- cols:(\d+) -->", line.strip())
        if m and not in_block:
            want = int(m.group(1))
            continue
        if line.startswith("```"):
            if not in_block:
                in_block = True
                if want:
                    blocks += 1
            else:
                in_block = False
                want = None
            continue
        if in_block and want and width(line) > want:
            errors += 1
            print(f"{path}:{n}: {width(line)} > {want}: {line[:60]}...")
    print(f"{blocks} width-checked blocks, {errors} overflowing lines")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
