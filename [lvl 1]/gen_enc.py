from pwn import xor

IAT = {
    "VirtualAllocEx": "",
    "WriteProcessMemory": "", 
    "CreateRemoteThread": "",
    "WaitForSingleObject": "",
    "VirtualFreeEx": "",
    "shellCode_32": "",
    "shellCode_64": "",
}

key = "rzdhop_is_a_nice_guy".encode()

# Chiffrement des noms d'API
for IA in IAT:
    IAT[IA] = xor(IA.encode(), key).hex()

# Dump
for k, v in IAT.items():
    print(f"{k} = {v}")
print(f"Key = {key.hex()}")
