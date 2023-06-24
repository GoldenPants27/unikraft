#include <uk/config.h>

#include <stddef.h>
#include <stdio.h>
#include <errno.h>

#include <uk/plat/bootstrap.h>
#include <uk/essentials.h>

//extern unsigned int boot_time;

int main(int argc, char *argv[]) __weak;

void ukplat_entry_argp(char *arg0, char *argb, __sz argb_len)
{
	ukplat_entry(0, &arg0);
}

void ukplat_entry(int argc, char *argv[])
{
	int rc = 0;

	/* Compute boot time till main() call */
	// __asm__ ("movq	%rax, %rbx;"
	// 		 "xorl	%eax, %eax;"
	// 		 "lfence;"
	// 		 "rdtsc;"
	// 		 "lfence;"
	// 		 "subl	$boot_time, %eax;"
	// 		 "movl	%eax, boot_time;"
	// 		 "movq	%rbx, %rax;");

	// printf("boot time: %d\n", boot_time);

    /* Call main */
	rc = main(argc, argv);
	rc = (rc != 0) ? UKPLAT_CRASH : UKPLAT_HALT;

	ukplat_terminate(rc); /* does not return */
}
