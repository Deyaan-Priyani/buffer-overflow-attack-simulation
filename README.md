# Stack Buffer Overflow Attack Simulation

A small C lab that shows how oversized input can change a mock access flag.
It runs only inside its own test program and does not connect to another service.

## What happens

The program places a **16-byte name buffer** next to a four-byte access flag on
the stack. The flag starts at zero: access denied. In `vulnerable` mode, copying
**20 A characters** fills the buffer and overwrites the flag. The program prints
`RESULT=GRANTED`, simulating a bypass of an access check.

`fixed` mode rejects inputs of 16 bytes or more, leaving room for the string's
ending zero byte. Vulnerable mode has a 23-byte lab limit to keep the intended
overwrite inside the enclosing structure. Overflowing its name buffer is still
undefined behavior in C, so results can vary across builds. This changes nearby
data rather than taking over the program's return address.

## The three files

- `buffer_overflow.c`: the vulnerable copy and the length-checked fix.
- `test_cases.py`: compiles the program and checks 25 inputs in both modes.
- `README.md`: explains the lab and commands.

## Compile and run

On Linux with GCC and Python 3 installed:

```bash
gcc -std=c11 -Wall -Wextra -Wpedantic -g -O0 buffer_overflow.c -o buffer_demo
./buffer_demo vulnerable AAAAAAAAAAAAAAAAAAAA
./buffer_demo fixed AAAAAAAAAAAAAAAAAAAA
python3 test_cases.py
```

**GCC** compiles C into a runnable program. `-g` adds debugging information, and
`-O0` makes the example easier to inspect. Python checks short, oversized and
UTF-8 inputs, including lengths around the buffer boundary. It builds in a
temporary folder and removes its test binary afterward.

Expected test summary: **25 inputs, 50 checks, 10 mock access grants in vulnerable
mode, and zero in fixed mode.** Fixed mode rejects 17 oversized inputs.

## Inspect the overwrite with GDB

**GDB means GNU Debugger.** After compiling with the command above:

```bash
gdb --args ./buffer_demo vulnerable AAAAAAAAAAAAAAAAAAAA
```

Inside GDB:

```gdb
break copy_unchecked
run
print input_length
set $state = session
print $state->access_flag
x/24bx $state
finish
print $state->access_flag
x/24bx $state
continue
```

The breakpoint pauses before copying. `print` shows the flag, `x/24bx` shows
24 bytes of memory, and `finish` completes the copy. Compare the flag afterward:
its four bytes should be `0x41` (the value of `A`). Data corruption does not
always cause a segmentation fault. Valgrind may miss this overwrite between
members of the same stack structure.

## Remote Linux and formatting

Copy the three files to a remote Linux server you are allowed to use. Log in
with **SSH** (Secure Shell), enter the folder and run the commands above:

```bash
ssh YOUR_USERNAME@YOUR_SERVER
cd buffer-overflow-attack-simulation
```

`clang-format -i buffer_overflow.c` formats the C file if installed. It changes
spacing and layout; GCC compiles, and GDB debugs.

## Why this matters

Memory mistakes still affect C software. Here, a small overwrite changes a
security decision. Input checks prevent this example; real software also needs
compiler protections and memory testing.

## Verification

The 50 checks passed locally on macOS using Apple Clang 17, which is also what
the local `gcc` command launches. The remote Linux/GNU GCC and GDB commands above
are instructions to repeat the lab; those sessions have not been verified here.
GDB, Valgrind and clang-format were not available in the local test environment.
