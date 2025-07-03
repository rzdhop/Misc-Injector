> CE PROJET EST À VOCATION PUREMENT ÉDUCATIVE. Il est nécessaire de comprendre les malwares pour pouvoir les analyser (reverser), c'est donc dans cette mentalité que j'ai décidé de créer mon propre malware de plus en plus complexe et non détectable.

📄 Voir [EULA.md](./EULA.md) pour les conditions d'utilisation.

##### Process injector level 0
les shellcodes sont obtenu avec : 
```
64 bit Shellcode : msfvenom --platform windows -p windows/x64/messagebox TEXT="Injected by Rida" TITLE="Pwned" EXITFUNC=thread -f c
32 bit shellcode : msfvenom -p windows/messagebox -a x86 --platform windows TEXT="Injected by Rida" TITLE="Pwned" EXITFUNC=thread -f c
```

POC : 

![image](assets/POC_lvl_0.png)

Detection: 

![alt text](assets/detect_lvl_0.png)

##### Process injector level 1
> Import dynamique et XOR des noms de fonctions et shellcodes

POC : 

![image](assets/POC_lvl_1.png)

Detection : 

![image](assets/detect_lvl_1.png)

##### Process injector level 2
> Imports dynamisque obfusqué sur plus de fonctions, detection basique de VM + Debugger

> implementation d'une techique de faire grossir le process en mémoire pour timeout les AVs

POC :

![image](assets/POC_lvl_2.png)

Detection : 

![alt text](assets/detect_lvl_2.png)


##### Process injector level 3
> Imports dynamisque obfusqué sur plus de fonctions, detection basique de VM + Debugger

> implementation d'une techique de faire grossir le process en mémoire pour timeout les AVs

> Indirect Syscall (ntdll trampoline) (obfuscation avec insruction parasites)

> custom GetProcAddress

POC : 

![image](assets/POC_lvl_3.png)

Detection (Sans Custom GetProcAddress)

![aimage](assets/detect_lvl_3.png)

##### Process injector level 4
> Binary signing using Digicert/leaked certificates or Openssl 

- `openssl req -x509 -newkey rsa:4096 -keyout malkey.pem -out malcert.pem -sha256 -days 365`
- `openssl pkcs12 -inkey key.pem -in cert.pem -export -out sign.pfx`
- `signtool sign /f sign.pfx /p <pfx-password> /t http://timestamp.digicert.com /fd sha256 binary.exe`

> 

##### DLL injector level 0
POC : 

![image](assets/POC_DLL_lvl_0.png)

Detection : 
Bon ça sert a rien c'est niveau 0


