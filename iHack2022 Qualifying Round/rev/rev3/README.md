# Rev-03

There are 3 ways to solve this challenge:
1. XOR the flag bytes with the key, and perform ROT13.
2. Solve `crackme` function:
    - The first input is asking for a password. Perform ROT13 "cyx" for the password.
    - Second input is asking for a passcode. Perform arithmetic operations based on the decompiled source code:
  ```
            int password = 0xaabbccdd; 
            int password2 = (password + 5) * 2 - 3;
            int password3 = (password2 >> 0xa) * 2 - 3;
            int password4 = sqrt(password3);
            int password5 = (int)(log(password4) / log(3));
            //printf("%d\n", password3 + password4 - password2 << password >> password5);
            if (pass == password3 + password4 - password2 << password >> password5)//8388608
  ```
  3. Patch the jump through dynamic debugging.
