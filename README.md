# Linux process hollowing

Code samples to perform process hollowing on Linux. Full article here: [https://www.bencteux.fr/posts/linux_process_hollowing/](https://www.bencteux.fr/posts/linux_process_hollowing/)

## Ptrace code injection

Compile:

```
$ gcc -c hollowing_ptrace hollowing_ptrace.c 
```

Run:

```
$ ./hollowing_ptrace /usr/lib/firefox-esr/firefox-esr
```

Check:

```
ps aux | grep firefox
cat /proc/<pid>/cmdline
pidof firefox-esr
```

