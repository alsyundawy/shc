# 🛡️ SHC - Shell Script Compiler 🚀

Generic Shell Script Compiler with Enhanced Security & Auditing

[![Latest Version](https://img.shields.io/github/v/release/alsyundawy/shc)](https://github.com/alsyundawy/shc/releases)
[![Build Status](https://img.shields.io/travis/alsyundawy/shc/release)](https://travis-ci.org/alsyundawy/shc)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-Passing-brightgreen.svg)](https://github.com/alsyundawy/shc)
[![Bash](https://img.shields.io/badge/Shell-Bash%205%2B-orange.svg)](https://github.com/alsyundawy/shc)
[![Maintenance Status](https://img.shields.io/maintenance/yes/9999)](https://github.com/alsyundawy/shc/)
[![License](https://img.shields.io/github/license/alsyundawy/shc)](https://github.com/alsyundawy/shc/blob/master/LICENSE)

[![GitHub Issues](https://img.shields.io/github/issues/alsyundawy/shc)](https://github.com/alsyundawy/shc/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alsyundawy/shc)](https://github.com/alsyundawy/shc/pulls)
[![GitHub Stars](https://img.shields.io/github/stars/alsyundawy/shc?style=social)](https://github.com/alsyundawy/shc/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alsyundawy/shc?style=social)](https://github.com/alsyundawy/shc/network/members)
[![GitHub Contributors](https://img.shields.io/github/contributors/alsyundawy/shc?style=social)](https://github.com/alsyundawy/shc/graphs/contributors)

[![Donate with PayPal](https://img.shields.io/badge/PayPal-donate-orange)](https://www.paypal.me/alsyundawy)
[![Sponsor with GitHub](https://img.shields.io/badge/GitHub-sponsor-orange)](https://github.com/sponsors/alsyundawy)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

Empowering Developers • Securing Shell Scripts • Open Source Passion

---

## 📖 Overview

**Shc** takes a script, which is specified on the command line, and produces **C source code**. The generated source code is then compiled and linked to produce a stripped binary executable.

> **Insight:** `shc` itself is not a compiler such as `cc`. It rather encodes and encrypts a shell script and generates C source code with an added expiration capability. It then uses the system compiler to compile a stripped binary which behaves exactly like the original script. Upon execution, the compiled binary will decrypt and execute the code with the shell `-c` option.

*Note: The compiled binary will still be dependent on the shell specified in the first line of the shell code (i.e. shebang `#!/bin/sh`), thus `shc` does not create completely independent binaries.*

---

## ⚡ Installation

### 🛠️ Building & Installing Locally

First, clone the repository and ensure you have the necessary packages for compiling:

```bash
# Clone the repository
git clone https://github.com/alsyundawy/shc.git
cd shc

# Install dependencies
sudo apt-get update
sudo apt-get install build-essential automake autoconf libtool
```

Then, compile and install from the source:

```bash
./autogen.sh
./configure
make
sudo make install
```

*(**Note:** If `make` fails due to **automake**'s version, ensure you have run `./autogen.sh` before running the commands.)*

### 🐧 Debian GNU/Linux and Ubuntu Systems

```bash
sudo apt-get install shc
```

### 📦 Ubuntu Systems (via PPA Repository)

```bash
sudo add-apt-repository ppa:alsyundawy/ppa
sudo apt-get update
sudo apt-get install shc
```

> **Prefer Pre-compiled Binaries?**
> Download a compiled binary package from the [Releases Page](https://github.com/alsyundawy/shc/releases/latest) and copy the `shc` binary to `/usr/bin` and `shc.1` to `/usr/share/man/man1`.

---

## 💻 Usage

```bash
# General Usage
shc [options]

# Compile a script into a binary
shc -f script.sh -o binary

# Untraceable binary (prevents strace, ptrace, etc.)
shc -U -f script.sh -o binary  

# Untraceable binary, no root required (only sh scripts, no parameters)
shc -H -f script.sh -o binary  
```

### 🛡️ The Hardening Flag `-H`

This flag is currently in an **experimental state** and may not work on all systems. This flag only works for the **default** shell. For example, if you compile a **bash** script with the `-H` flag, the resulting executable will only work on systems where the default shell is **bash**. You may change the default shell, which generally is `/bin/sh` (often a symlink to bash or dash).

⚠️ **Notice:** `-H` does not work with positional parameters (yet).

---

## 🧪 Testing

To run the test suite, simply use:

```bash
./configure
make
make test
```

Temporary directories are generated in `${TMPDIR:-/tmp}/shc.SHELL.OPT.XXXXXX` (caps are replaced according to the test). When a test succeeds, the directory is removed; if it fails, it is kept to help with debugging.

Clean up test outputs manually with:

```bash
rm -rf ${TMPDIR:-/tmp}/shc.*
```

---

## ⚠️ Known Limitations

- **SCRIPT Length:** The `_SC_ARG_MAX` system configuration parameter limits the length of the arguments to the `exec` function. With standard options, this limits the maximum length of the runnable script of shc. However, you can now use the `-P` option which uses a pipe to circumvent this limitation.

> **❗ CHECK YOUR RESULTS CAREFULLY BEFORE USING ❗**

---

## 🔒 CHANGES - Audit & Hardening

> **By HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION**

### 🌟 LATEST: MON Jun 15 19:52:11 WIB 2026 - HARRY DS ALSYUNDAWY - ALSYUNDAWY IT SOLUTION

- **Feat**: Added absolute out-of-the-box compiler support for modern & legacy shells: `ksh88`, `ksh93`, `mksh`, `pdksh`, `fish`, `nu`, `pwsh`, `powershell`, `yash`, `osh`, `elvish`.
- **Feat**: Added global compatibility support for `#!/usr/bin/env` wrapper interpretation with complex parameter chaining.
- **Fix**: Fixed critical bug where `sscanf` truncated whitespace-separated shebang options (e.g., `env -S bash -e`).
- **Fix**: Fixed ARC4 encryption synchronization bug that passed raw binary ciphertexts to `execvp` wrappers causing abnormal behavior on `env` and `sh` variants.
- **Qual**: Fixed internal state corruption and unsafe globbing mechanisms in `test/match`.
- **Qual**: Hardened script headers using strict execution parameters (`set -eu`) across all POSIX payload testing scripts (`test/match`, `test/pru.sh`).
- **Qual**: Replaced outdated and fragile string parsing echo with robust printf logic inside standard testing scripts.
- **Sec**: Implement strict Shell options (`set -Eeuo pipefail`) & safe IFS parsing in `test/ttest.sh`.
- **Sec**: Fix `mktemp` template vulnerabilities in `test/ttest.sh` to prevent predictable temp directories.
- **Qual**: Add resilient OS-signal cleanup traps (EXIT, INT, TERM) to prevent orphan artifacts in `test/ttest.sh`.
- **Qual**: Refactor arithmetic and shell evaluations to pass strict ShellCheck compliance (fixed SC2034, SC2145, SC2162, suppressed SC2329).
- **Qual**: Enable strict error handling (`set -e`) in `autogen.sh`.
- **Qual**: Fixed IDE C linting warnings in `src/shc.c` (removed unused headers, fixed array string missing comma, improved conditional statements).
- **Feat**: Bumped internal version tag explicitly to `'4.0.3 (Hardened Audit Edition - 15 Jun 2026)'`.
- **Qual**: Synchronized Autotools `configure.ac` to version `4.0.3-Hardened-Audit-2026`.
- **Qual**: Fixed massive Markdown linting errors (MD041, MD012, MD010) across ChangeLog and README.md.
- **Fix**: Fixed double-percent formatting escape bug in `shc.c` causing `sh: 1: %s: not found` error during `-H` hardened compilation.
- **Fix**: Added `SKIP_OPTS` support to `test/ttest.sh`; set `SKIP_OPTS=-H` in CI sanitize job to skip `-H` tests that are fundamentally incompatible with ASAN `LD_PRELOAD` injection.

*Original Credit to [@alsyundawy](https://github.com/alsyundawy)*

### 🕒 LATEST: Aug 19 2024

- **Feat**: Piping (`-P`, `-p`), with `$0` forging (big scripts, perl, python) @fabio-brugnara.
- **Qual**: Enhance tests (Check stderr, forging, tempdir, complex arguments), option SKIP (tests) @mdeweerd.
- **Qual**: Add Github CI flox (build, run tests with(out) sanitizer, generate files) @mdeweerd.
- **Fix**: Fix memory leaks in generated c-code @mdeweerd.
- **Fix**: Fix memory leaks in generation c-code @ashamedbit #165
- **Fix**: Fix static code checks/implement recommendations (prevent leaks, overflows) @mdeweerd.
- **Qual**: Add static code checks, linting, code formatting @mdeweerd #162 #161
- **Doc**: Improvements to the documentation @mdeweerd #163 #160
- **Doc**: Add code block hinting for Ubuntu PPA install procedure lb803 #164
- **Feat**: Remove `ash` dependency @dviererbe #167
- **Fix**: Fix for script filenames with spaces/special characters @ergoucao #157.
- **Feat**: Option `-2` to use mmap2 @csersoft #132
- **Doc**: Fix automatic hyperlinks by removing `<>` @learnpassword #148
- **Doc**: Fix typo in usage @ghost #129
- **Fix**: Fix strip in case of cross-compilation @embexus #125
- **Fix**: Fix NULL-ptr dereference in shhl string @RKX1209 #83

*Original Credit to [@mdeweerd](https://github.com/mdeweerd)*

---

## 🤝 Contributing

We welcome your open-source passion! If you want to make pull requests, please target the **`master`** branch. The default branch is **`release`**, which should contain clean package files ready to be used.

### 📝 Documentation & Manuals

If you want to edit the manual, please edit the **`man.md`** file. The CI flow will automatically generate the other manual files from it.
You can also generate these locally with the following commands (requires `pandoc`):

```bash
pandoc -s man.md -t man -o shc.1
# Also run this command to generate the HTML manual
pandoc -s man.md -t html -o man.html
```

### ⚙️ Autotools

If you change anything related to `autotools`, `./autogen.sh` should be run to regenerate the derived files. Again, the CI flow will generate these automatically.
*(You may need to pull after a push because of the changes committed by CI.)*

---

## 🏆 Credits & Acknowledgements

This project is a hardened and heavily audited iteration built upon the incredible foundational work of **[neurobin](https://github.com/neurobin)**.
Huge thanks to the original author and the contributors of the [neurobin/shc](https://github.com/neurobin/shc) repository.

---

## 🔗 Links

1. [Man Page](https://alsyundawy.github.io/shc/man.html)
2. [Web Page](https://alsyundawy.github.io/shc)

---
Developed with ❤️ & Passion by Open Source Community
