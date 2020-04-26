GDB inspect program

	break linenum --- breakpoint at line linenum
	break Test::generateTestPath
	info variables --- info of all variables
	info variables text --- info of all variables matching regexp text
	help info locals --- help for command info locals
	info locals --- Local variables of current stack frame
	info scope main --- List the variables local to a scope (main)
	info registers --- list and content of registers
	print variable --- prints content of variable
	bt full --- prints backtrace of all stack frames and local variables
	list --- lists source code
	info address variable --- address of variable
	x address --- examine memory address
	x/10x $sp
	start -- run program until beggining of main (instead of breaking)
	step -- continue until it reaches a different source line (step into)
	next -- step over subroutines
	r -- run program
	r arg1 arg2 arg3 -- run program with arguments
	directory /tmp/ -- to add /tmp to the search path for source files
