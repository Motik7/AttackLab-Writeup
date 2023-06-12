# Phase 2

## Attack Lab Spec

Phase 2 involves injecting a small amount of code as part of your exploit string.
Within the file `ctarget` there is code for a function `touch2` having the following C representation:  
```
void touch2(unsigned val)
{
  vlevel = 2; /* Part of validation protocol \*/
  if (val == cookie) {
    printf("Touch2!: You called touch2(0x%.8x)\n", val);
    validate(2); 
  } else {
    printf("Misfire: You called touch2(0x%.8x)\n", val);
    fail(2);
  }
  exit(0);
}                                                      
```
Your task is to get `CTARGET` to execute the code for `touch2` rather than returning to `test`. In this case,
however, you must make it appear to `touch2` as if you have passed your cookie as its argument.  

**Some Advice:**  
• You will want to position a byte representation of the address of your injected code in such a way that `ret` instruction at the end of the code for `getbuf` will transfer control to it.  
• Recall that the first argument to a function is passed in register `%rdi`.  
• Your injected code should set the register to your cookie, and then use a `ret` instruction to transfer control to the first instruction in `touch2`.  
• Do not attempt to use `jmp` or `call` instructions in your exploit code. The encodings of destination addresses for these instructions are difficult to formulate. Use `ret` instructions for all transfers of 
control, even when you are not returning from a call.

Among other things the following image was provided. It is also useful to note that c3 is the hex encoding for the ret instrucition.
![image](https://github.com/Motik7/AttackLab-Writeup/assets/60900283/5eb247a9-f732-44bc-9ae4-75f597f749e4)

## Analysis

It's clear that we need to get to `touch2` from `getbuf`. Looking at `getbuf` in cobjectdum we see the following code:  
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
a function exits. We can confirm this by considering that we add 0x18 back to the rsp and then retq, which pops the value held at rsp and then goes to it. Therefore, if we can inject 0x18 bytes of random values and then the address of `touch2` when `retq` attempts to return to the address pointed to by rsp, it'll be our address. Looking again through the object dumb for `touch1` we see  
`0000000000401800 <touch2>`  
which tells us that our `touch2` function is at address 0x401800. We remember that x86-64 operates on little endian, and thus in our string the address must be formatted correctly.

However, before we can enter `touch2` we first must put our cookie into register `%rdi`. To do this, we'll have to take our return address into some code that we'll write to put the cookie into `%rdi`. We can accomplish this by writing code within the 0x18 initial string bytes, and then returning within it which will begin running the code. However, we need to know where that is. To accomplish that goal, we'll use GDB on ctarget.
