# libxmp-lite-ps2-mseek-seekend-oob-read
# libxmp-lite-ps2-mseek-seekend-oob-read

## Vulnerability Summary
Missing bounds check in the `SEEK_END` case of `mseek()` in `memio.c` of libxmp-lite-ps2.
The function allows `m->pos` to be set to a value greater than `m->size`.
Built-in read APIs `mgetc()` / `mread()` are guarded by `CAN_READ()` and do **not** trigger this out-of-bounds access.
The vulnerability manifests only when caller code directly uses the unchecked `m->pos` to index the underlying buffer, resulting in a **stack-based out-of-bounds read (CWE-125)**.

## Affected Component
libxmp-lite-ps2, `memio.c`, function `mseek()`

## Reproduction
Environment: Ubuntu, clang + AddressSanitizer
```bash
clang -fsanitize=address -g seekend_poc.c -o seekend_poc
./seekend_poc

Crash Evidence
plaintext
pos = 257, buffer size = 256
=================================================================
==7038==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffec8516d61 at pc ...
READ of size 1 ...
Full ASan log is included in this repo.
Patch
Add bounds validation for newpos in the SEEK_END branch:

case SEEK_END:
	if (m->size < 0)
		return -1;
	{
		long newpos = m->size + offset;
		if (newpos < 0 || newpos > m->size) {
			return -1;
		}
		m->pos = newpos;
	}
	return 0;
CWE
CWE-125: Out-of-bounds Read
Note
This is a stack-based out-of-bounds read, not a stack buffer overflow (CWE-121). ASan stack-buffer-overflow label applies to both read and write out-of-bounds access on stack memory.
plaintext

