# Rev-04

1. A remote thread is created to store the shellcode. The shellcode is XOR encrypted with the key.
2. Extract the shellcode from the executable.
3. XOR decrypt shellcode with key and save as `.bin`.
4. Analyze the shellcode in `scdbg`.
