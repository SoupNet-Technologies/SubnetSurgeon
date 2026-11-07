# SPEC — SubnetSurgeon

## Purpose

A Tkinter GUI covering roughly 40 subnetting operations for IPv4 and IPv6: subnet IDs, masks, broadcast and network addresses, usable ranges, CIDR conversions, wildcard masks, supernets, binary conversions, validation, and generators. Built for study and day-to-day network admin math. Internal name is `SNT-SS` / "SoupNet Technologies Subnet Surgeon"; the window title says "SoupNet Technologies Subnet Surgeon".

Authorized use note: pure arithmetic on addresses you type in — no packets leave the machine, nothing is scanned. Nothing to authorize.

## Quick facts

- Language: Python 3
- Deps: stdlib only (`tkinter`, `ipaddress`, `random`)
- Entry point: `sntss.py`
- Test file: `test_sntss.py` (unittest, 29 test methods)
- Run: `python sntss.py`
- Tests: `python -m unittest test_sntss`

## Architecture

Single file, ~1040 lines, one class `SNTSS`. The UI is a menu-driven frame switcher:

- `__init__` builds a scrollable canvas (mousewheel bound globally via `bind_all`), 600x500 window
- `create_main_menu()` lays out one button per operation; `execute_selected_function()` dispatches
- each operation has a `show_*` method (builds the input form via `create_entry_fields`) and a `calculate_*` method (does the math, shows the result in a messagebox)
- `back_to_menu()` returns to the main menu; `clear_frame()` handles teardown
- `create_tooltip()` attaches hover hints to widgets

The menu (as registered in `create_main_menu`) includes, beyond what the README lists: wildcard mask (IPv4), validate IP / validate subnet mask (IPv4), supernet (IPv4 and IPv6), network address, first/last usable IP, prefix length, public/private check, default gateway, same-subnet check, random IP and random subnet mask generators, IP↔binary both ways (IPv4), and the IPv6 set: subnet ID, prefix length, network address, in-subnet check, random IPv6, IPv6↔binary, unicast check, unique-local check.

## Interfaces

GUI only — no CLI, no importable stable API (the `calculate_*` methods are coupled to tk widgets). Inputs are text fields; results go to messageboxes.

The `ipaddress` module does most validation-heavy lifting; several operations explicitly handle both IPv4 and IPv6 through `ipaddress.ip_network` (noted in source comments).

## Data & storage

None. Stateless; nothing is saved, nothing is read.

## Testing

`test_sntss.py` exists and is real: 29 `unittest` methods in `TestSntssFunctions`, instantiating the actual `SNTSS` tkinter app (withdrawn window). Coverage focuses on `calculate_number_of_hosts` (slash 32/31/30/24, CIDR and mask forms, invalid inputs), `calculate_mask` (valid/non-integer/out-of-range CIDR), IPv6 subnet ID (valid, bad prefix, bad address), and the random IP/IPv6 generators (slash 128/127/64, invalid inputs).

Note: tests instantiate Tk, so they need a display; headless CI will fail without `Xvfb` or similar.

## Limitations & known issues

- The README's feature list is about half the actual menu — it predates the wildcard/supernet/IPv6/random/binary additions. README also says `cd sntss` after cloning, but the repo directory is `SubnetSurgeon`
- `bind_all("<MouseWheel>")` means the scroll handler fires even when the mouse is over non-canvas widgets
- Results are delivered in modal messageboxes — no copyable output pane, no history
- No packaging (`pyproject.toml`/`setup.py` absent); run from the repo directory
- One git-ignored file pattern covers `.DS_Store`-style cruft; nothing else unusual

## File map

```
sntss.py         the application: SNTSS class, ~1040 lines
test_sntss.py    unittest suite, 29 tests, needs a display
README.md        existing, partially stale feature list
LICENSE          present (1 KB)
```
