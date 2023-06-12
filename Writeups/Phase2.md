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
inputs whatever we enter into the stack. This pens up the opportunity for code injection. For phase 2, this is putting our cookie into `%rdi` then calling `touch2`. Therefore, if we can inject 0x18 bytes of random values and then the address of `touch2` when `retq` attempts to return to the address pointed to by rsp, it'll be our address. Looking again through the object dumb for `touch2` we see  
`0000000000401800 <touch2>`  
which tells us that our `touch2` function is at address 0x401800. We remember that x86-64 operates on little endian, and thus in our string the address must be formatted correctly.

However, before we can enter `touch2` we first must put our cookie into register `%rdi`. To do this, we'll have to take our return address into some code that we'll write to put the cookie into `%rdi`. We can accomplish this by writing code within the 0x18 initial string bytes, and then returning within it which will begin running the code. However, we need to know where that is. To accomplish that goal, we'll use GDB on ctarget. 

### GDB Analysis

#### Finding `%rsp`

Before that, we need to know where to set certain breakpoints to be able to inspect our code well. A valuable place to put the breakpoint would be `getbuf` since ultimately it is where we do our injection, and will show us where the stack pointer `%rsp` is at any moment we choose to see. GDB allows us to simply put breakpoints at functions using `b <function_name>` so using `b getbuf` will put a breakpoint at the right spot. We then run with `r` and for now we won't include any argument. We hit the breakpoint and use `i r` to show information regarding the registers. We see that  
`rsp            0x556424c0          0x556424c0`  
which gives us a good idea of where `%rsp` is, however it's not the one that we want. At this point, we haven't decremented the stack, and while we could manually deduct 0x18 from the value we see, it's easier to run `si` and let the code do it for us. Thus, we see  
`rsp            0x556424a8          0x556424a8`  
From this, we now know where our string starts, and where we could potentially inject code. We have confirmation this does not change between runs, so we can safely continuously use this.

## Solution

Now that we have all of the information we need, we can put it all together. The plan of attack is to inject two pieces of code, a `pop rdi` and a `ret`. Referring to the info provded above, these are `5f` and `c3` respectively. We still need to pad out the rest of the 0x18 so we are now at  
`5f c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00`  
Now we need to go to our injected code. From our GDB analysis, we see that the string starts at 0x556425a8. Therefore we add this in overwriting the return address of `getbuf`. Using little endian notation as is required, this yields  
`5f c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a8 24 64 55`  
However, we are still not done. Consider that `pop rdi` pops whatever `%rsp` points to and puts it into `%rdi`. The `retq` in `getbuf` will move `%rsp` past the return address we injected. We therefore need to append what we want in `%rdi` after our return address. We look in cookie.txt to see that our cookie is 0x32bf3fc2. Therefore, following little endian protocol we append it to yield  
`5f c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a8 24 64 55 c2 3f bf 32`  
This will not work. The reason for this is that ret reads 8 bytes and we have only provided 4. This will not work as intended, so we pad it out to yield  
`5f c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a8 24 64 55 00 00 00 00 c2 3f bf 32`  
Now we have our cookie in `%rdi`, and we need to `ret` into `touch2`. `c3` will accomplish this, but once again we need to put the return address into our stack. Putting it all together, we get a final solution of  
`5f c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a8 24 64 55 00 00 00 00 c2 3f bf 32 00 00 00 00 00 18 40 00`
