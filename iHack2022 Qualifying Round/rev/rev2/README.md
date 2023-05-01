# Rev-02

> **Challenge Description:** Can you reverse a Rust program?
>
> **Flag Format:** `ihack{MD5}`

### Solution

Decompile the given binary in `Ghidra` and navigate to the function `check_flag`:

```c
void rev2::check_flag(undefined8 param_1)

{
  === STRIPPED ===
  
  === STRIPPED ===
  
  if (uVar2 < 10) {
                    /* WARNING: Subroutine does not return */
    core::panicking::panic
              ((panicking *)
               "attempt to subtract with overflowih8dae47166}58458e5caedcd1cfd059f81ack{Correct!\n",
               (&str)CONCAT115(in_stack_fffffffffffffea7,
                               CONCAT114(in_stack_fffffffffffffea6,
                                         CONCAT113(in_stack_fffffffffffffea5,
                                                   in_stack_fffffffffffffe98))));
  }
  auVar5 = <alloc::string::String_as_core::ops::index::Index<core::ops::range::Range<usize>>>::index
                     (param_1,6,uVar2 - 10,&DAT_00153b38);
  uVar2 = alloc::string::String::len(param_1);
  if (9 < uVar2) {
    auVar6 = <alloc::string::String_as_core::ops::index::Index<core::ops::range::RangeFrom<usize>>>
             ::index(param_1,uVar2 - 10,&DAT_00153b68);
    uVar7 = SUB168(auVar6 >> 0x40,0);
    bVar1 = str>::eq(SUB168(auVar3,0),SUB168(auVar3 >> 0x40,0),
                     "ih8dae47166}58458e5caedcd1cfd059f81ack{Correct!\n",2)
}
```

Rearrange the hardcoded flag by segmenting into multiple pieces: `ih`, `ack{`, `58458e5caedcd1cfd059f81`, `8dae47166}`.

**Flag:** `ihack{58458e5caedcd1cfd059f818dae47166}`
