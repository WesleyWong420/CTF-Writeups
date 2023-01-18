
builtin_arrays = vars(__builtins__)
builtin_func_import = builtin_arrays["\x5f_\u0069\155p\u006fr\u0074\137_"]
inspect_py = builtin_func_import("\151\u006esp\x65\U00000063t")
func_vars = builtin_arrays["v\x61\U00000072\x73"]
get_source_at_add = func_vars(inspect_py)["\147\x65\164\x73\U0000006fu\U00000072\u0063e"]
sys_builtin = builtin_func_import("\U00000073\u0079s")
func_print = builtin_arrays["\x70\162\u0069nt"]
whole_obf_code = get_source_at_add(func_vars(sys_builtin)["\x6d\U0000006f\144\x75\u006c\U00000065\163"]["_\U0000005f\u006d\141i\u006e\U0000005f_"])
stable_py_arg1 = func_vars(sys_builtin)["\x61\U00000072g\x76"]
exit = func_vars(sys_builtin)["\u0065\x78i\U00000074"]
re_py = builtin_func_import("\x72\u0065")
find_all_at_addr = func_vars(re_py)["\x66\u0069\156\x64a\U0000006c\x6c"]
array_of_obfs_var = find_all_at_addr('_?([^\n?\\[\\]\']+?)\\s=', whole_obf_code)
class_str = builtin_arrays["s\164\u0072"]
join_str = func_vars(class_str)["j\157\x69n"]
joined_obfs_vars = join_str("", array_of_obfs_var)
ljustify_str = func_vars(class_str)["\154\x6au\u0073\164"]
math_buildin = builtin_func_import("\x6d\141\U00000074\x68")
len_builtin = builtin_arrays["\U0000006cen"]
ceil_builtin = func_vars(math_buildin)["\x63e\U00000069\x6c"]
digit_8 = 1 << 3
joined_obfs_var_fakebase64 = ljustify_str(joined_obfs_vars, ceil_builtin(len_builtin(joined_obfs_vars) / digit_8) * digit_8, chr(0x3d))
base64_py = builtin_func_import("\U00000062a\x73e\U000000364")
ord_bultin = builtin_arrays["\x6f\162\u0064"]
b32_decode_at_addr = func_vars(base64_py)["\U0000006232\U00000064e\143\U0000006fd\145"]
bunch_of_hex = b32_decode_at_addr(joined_obfs_var_fakebase64)
lzma_py = builtin_func_import("\u006c\172m\141")
list_class = builtin_arrays["li\u0073\x74"]
decompress_at_addr = func_vars(lzma_py)["d\U00000065\x63\U0000006fm\u0070\162e\163\x73"]
decompressed_hex = decompress_at_addr(bunch_of_hex)
digit_2 = len_builtin(stable_py_arg1)
class_bytes = builtin_arrays["b\171\U00000074\x65s"]
if digit_2 < 2:
    func_print("N\x6ft\40\U00000065nou\147\u0068 \x61\u0072\147\u0075me\x6e\164\u0073")
    exit(1)
my_arg_1 = stable_py_arg1[1]
digit_7 = 7
eval_builtin = builtin_arrays["\U00000065\166\U00000061l"]
my_arg_length = len_builtin(my_arg_1)
if my_arg_length < digit_7:
    func_print("\U00000061r\U00000067\x20\151\x73\40t\U0000006f\157\x20\U00000073\x68\u006fr\164")
    exit(1)
flag = list_class(decompressed_hex)
flag[235] = ord_bultin(my_arg_1[0])
flag[515] = ord_bultin(my_arg_1[1])
flag[507] = ord_bultin(my_arg_1[2])
flag[519] = ord_bultin(my_arg_1[3])
flag[1552] = ord_bultin(my_arg_1[4])
flag[1586] = ord_bultin(my_arg_1[5])
flag[1617] = ord_bultin(my_arg_1[6])
flag_in_bytes = class_bytes(flag)
marshal_builtin = builtin_func_import("m\x61\162\U00000073h\U00000061\154")
loads_builtin = func_vars(marshal_builtin)["\x6co\u0061\U00000064\x73"]
O4SAAANABOIBGAAAV4ELSDVRYRT7WAQAAAAAABCZLI = loads_builtin(flag_in_bytes)
try:
    print(flag_in_bytes)
    eval_builtin(O4SAAANABOIBGAAAV4ELSDVRYRT7WAQAAAAAABCZLI)
except:
    func_print("T\150\x69s\u0020\U00000069s \166e\162\u0079 un\x73t\u0061b\x6c\U00000065,\u0020\x68\165\U00000068?")
    exit(1)
