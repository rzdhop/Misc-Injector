> CE PROJET EST À VOCATION PUREMENT ÉDUCATIVE. Il est nécessaire de comprendre les malwares pour pouvoir les analyser (reverser), c'est donc dans cette mentalité que j'ai décidé de créer mon propre malware de plus en plus complexe et non détectable.

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
