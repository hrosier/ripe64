# RIPE64: a 64bit port of the Runtime Intrusion Prevention Evaluator
This repository presents a 64-bit port of the [RIPE benchmark](https://github.com/johnwilander/RIPE).
RIPE was originally developed by John Wilander and Nick Nikiforakis and
presented at the 2011 Annual Computer Security Applications Conference (ACSAC) in Orlando, Florida.

This port was developed by Hubert ROSIER for an academic project in the National University of Singapore.
The project was supervised by Professor Roland YAP and co-supervisor senior research fellow Gregory James DUCK
of the School of Computing of the National University of Singapore.

The 850 buffer overflow attacks implemented in the original version of RIPE has been re-implemented to work as a 64bit software.  
Few more attacks have been added also and now RIPE64 can run around than 2050 buffer overflow attack forms if
we consider each shellcode as different form else it has around 950 different attack forms.

## How to build and run
#### Build
To build the benchmark just run the `make` command.
It will create two executable file in the `build/` folder, one compiled by
`gcc` and the other by `clang`.
It will be compiled without stack protector (`-fno-stack-protector`) and with executable 
stack (`-z execstack`).  

#### Individual test
To run a specific attack, you need to specify all the dimensions like this:
```bash
 ./build/[gcc|clang]_attack_gen -l location -c code_ptr -i inject_param -t [direct|indirect] -f func_abused [-d t]
```
where:  
  - __location__ can be "stack", "heap", "bss" or "data"
  - __code\_ptr__ can be "ret", "baseptr", "funcptrstackvar", "funcptrstackparam",
"funcptrheap", "funcptrbss", "funcptrdata", "structfuncptrstack", "structfuncptrheap",
"structfuncptrbss", "structfuncptrdata", "longjmpstackvar", "longjmpstackparam",
"longjmpheap", "longjmpbss" or "longjmpdata"
  - __inject\_params__ can be "nonop","simplenop", "simplenopequival", "r2libc" or "rop"
  - __func\_abused__ can be "memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
    "strcat", "strncat", "sscanf", "fscanf" or "homebrew"

The attacks is successful is a shell has been spawned.  

#### Full benchmark
You can run all the possible attack forms by running the script `ripe_tester.py`:  
```bash
 ./ripe_tester.py [direct|indirect|both] n (gcc|clang|both) (VERBOSE_OPTIONS)
```

It accepts at least 2 pararameters, the first one to launch direct attacks, indirect or both;
the second is the number of times each attack should be launched.
The other parameters are optional, the third parameter specifies to use the gcc or clang executables or both.
The last one controls the output format:    
- "--only-ok": only prints the functional attacks  
- "--only-some": only prints the partly functional attacks  
- "--only-fail": only prints the non-functional attacks  
- "--no-ok": don't print the functional attacks  
- "--no-fail": don't print the non-functional attacks  
- "--only-summary": only prints the summary  
- "--format-bash"(default): prints the summary in plain text  
- "--format-latex": prints the summary as a latex table  
- "--format-bash-latex": pritns the summary in plain text and as a latex table  

Successful attacks are logged as "OK", the ones that failed are "FAILED", the ones that didn't succeed each round
are marked as SOME.  
The attacks logged as "NOT POSSIBLE" are the ones that are considered impossible such as overflowing a function pointer in the bss segment from the stack.

## Note
### ASLR
ASLR can be disabled temporary with:  
```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

### Ropper
[Ropper](https://github.com/sashs/Ropper) can find gadgets to build rop chains for different architectures.
It was used before the wanted gadgets were hardcoded in functions.

### Metasploit
The one byte NOP equivalent sled has been generated using the metasploit framework 
with the command:  
```
generate 40 -s rsp -t c
```
the `-s rsp` tells that we don't want to change the RSP register (I got errors without).  

[how to install](https://www.darkoperator.com/installing-metasploit-in-ubunt/)
