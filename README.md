# MiniExec - Executable generator for Shellcode and Powershell Scripts on Windows

## Why?
It's fun :D
And it is lighter than msfvenom :DDD.

During my OSCP practises I found it is really inconvenient to fire up 
metasploit everytime when I need to generate a custom payload.

And of course, meterpreter is banned in OSCP exam, and `shell_reverse_tcp` is not compatible with nc.
So I wrote this tool to generate executables for me to run powershell scripts and shellcodes.

After that, I realized that msfvenom has `windows/exec` available. Now I am crying because I wasted several hours for this :(((((.

## Usage
First, compile template-exe, template-dll, and template-service.
Or use the pre-compiled version in this repository.
Put these template files in your current working directory.

Use `miniexec.py` to generate your executables.

```
usage: miniexec.py [-h] [-t <type>] [-o <output>] [-f <script.ps1> | -p <payload> | -s <shellcode>]

options:
  -h, --help            show this help message and exit
  -t <type>, --type <type>
                        Type of the generated payload: exe,dll,service
  -o <output>, --output <output>
                        Path of generated executable
  -f <script.ps1>, --file <script.ps1>
                        Script file to be loaded
  -p <payload>, --payload <payload>
                        Oneline payload
  -s <shellcode>, --shellcode <shellcode>
                        Shellcode file
```

## Compile
Compile using MinGW, or whatever tools you prefer :)
### EXE
```bash
    x86_64-w64-mingw32-gcc exe.c -o template-exe "-Wl,--entry=_start" -nostartfiles -mwindows -nostdlib -lshell32 -lkernel32
    mv template-exe.exe template-exe
```

### DLL
Dll has two versions, one is using traditional ShellExecuteA with CreateThread, the other is using CreateProcess.
```bash
    x86_64-w64-mingw32-gcc dll.c -o template-dll "-Wl,--entry=_start" -nostartfiles -mwindows -nostdlib -lshell32 -lkernel32
    x86_64-w64-mingw32-gcc dll-createprocess.c -o template-dll "-Wl,--entry=_start" -nostartfiles -mwindows -nostdlib -lshell32 -lkernel32
    mv template-dll.exe template-dll
```

### Service EXE
```bash
    x86_64-w64-mingw32-gcc service.c -o template-service "-Wl,--entry=_start" -nostartfiles -mwindows -nostdlib -lshell32 -lkernel32 -ladvapi32
    mv template-service.exe template-service
```

