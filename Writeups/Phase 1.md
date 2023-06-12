
# Phase 1

_From attack lab spec:_  
For Phase 1, you will not inject new code. Instead, your exploit string will redirect the program to execute an existing procedure.
Function getbuf is called within CTARGET by a function test having the following C code:  
<code>void test()
{
  int val;
  val = getbuf();
  printf("No exploit. Getbuf returned 0x%x\n", val);
}</code>  
When `getbuf` executes its return statement (line 5 of `getbuf`), the program ordinarily resumes execution
within function `test` (at line 5 of this function). We want to change this behavior. Within the file `ctarget`,
there is code for a function `touch1` having the following C representation:  
<code>void touch1()
{
  vlevel = 1; /* Part of validation protocol */
  printf("Touch1!: You called touch1()\n");
  validate(1);
  exit(0);
}</code>  
Your task is to get `CTARGET` to execute the code for `touch1` when `getbuf` executes its return statement,
rather than returning to `test`. Note that your exploit string may also corrupt parts of the stack not directly
related to this stage, but this will not cause a problem, since `touch1` causes the program to exit directly.

## Analysis

It's clear that we need to get to `touch1` from `getbuf`. Looking at `getbuf` we see the following code:  
<code>00000000004017be <getbuf>:
  4017be:	48 83 ec 18          	sub    $0x18,%rsp
  4017c2:	48 89 e7             	mov    %rsp,%rdi
  4017c5:	e8 30 02 00 00       	callq  4019fa <Gets>
  4017ca:	b8 01 00 00 00       	mov    $0x1,%eax
  4017cf:	48 83 c4 18          	add    $0x18,%rsp
  4017d3:	c3                   	retq   
  </code>  
  Looking at the code, we see the following things happen. We put 0x18 bytes of storage on the stack, and then put our stack pointer into rdi.
  
