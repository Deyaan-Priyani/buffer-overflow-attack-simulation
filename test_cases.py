"""Compile the C demo and check 25 inputs in both modes. No packages needed."""

import argparse
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="gcc", help="C compiler (default: gcc)")
    args = parser.parse_args()
    source = Path(__file__).resolve().with_name("buffer_overflow.c")
    cases = [
        ("empty", ""),
        ("one character", "A"),
        ("short name", "Alice"),
        ("spaces", "hello world"),
        *[(f"{n} ASCII bytes", "A" * n) for n in range(14, 25)],
        *[(f"{n} ASCII bytes", "A" * n) for n in (32, 64, 256, 1024)],
        ("14 UTF-8 bytes", "é" * 7),
        ("16 UTF-8 bytes", "é" * 8),
        ("18 UTF-8 bytes", "é" * 9),
        ("punctuation", "!?@#$%"),
        ("20 digit bytes", "0" * 20),
        ("16 filler + 4 flag bytes", "A" * 16 + "BBBB"),
    ]
    assert len(cases) == 25
    grants = 0
    fixed_rejections = 0

    # Build outside the project folder and remove the binary when finished.
    with tempfile.TemporaryDirectory(prefix="buffer-demo-") as temporary:
        binary = Path(temporary) / "buffer_demo"
        subprocess.run(
            [args.cc, "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror",
             "-g", "-O0", str(source), "-o", str(binary)],
            check=True,
        )
        for label, text in cases:
            length = len(text.encode("utf-8"))
            outcomes = {}
            for mode in ("vulnerable", "fixed"):
                completed = subprocess.run(
                    [str(binary), mode, text], capture_output=True, text=True,
                    check=True, timeout=5,
                )
                fields = dict(line.split("=", 1)
                              for line in completed.stdout.splitlines())
                expected = (
                    "REJECTED" if mode == "fixed" and length >= 16 else
                    "DEMO_LIMIT" if mode == "vulnerable" and length >= 24 else
                    "GRANTED" if mode == "vulnerable" and length >= 17 else
                    "DENIED"
                )
                assert fields["MODE"] == mode, (label, fields)
                assert int(fields["INPUT_BYTES"]) == length, (label, fields)
                assert fields["ACCESS_BEFORE"] == "0", (label, fields)
                assert fields["RESULT"] == expected, (label, mode, fields)
                if expected == "GRANTED":
                    # Check the exact four bytes that should overwrite the flag.
                    flag = int.from_bytes(text.encode("utf-8")[16:20].ljust(4, b"\0"),
                                          byteorder=sys.byteorder)
                    assert int(fields["ACCESS_AFTER"]) == flag, (label, fields)
                    grants += 1
                else:
                    assert fields["ACCESS_AFTER"] == "0", (label, fields)
                fixed_rejections += mode == "fixed" and expected == "REJECTED"
                outcomes[mode] = expected
            print(f"PASS {label}: vulnerable={outcomes['vulnerable']}, "
                  f"fixed={outcomes['fixed']}")

    print("\n25 inputs x 2 modes = 50 checks passed.")
    print(f"Vulnerable mode: {grants} inputs changed the mock access flag.")
    print(f"Fixed mode: {fixed_rejections} oversized inputs rejected; "
          "0 mock access grants.")


if __name__ == "__main__":
    main()
