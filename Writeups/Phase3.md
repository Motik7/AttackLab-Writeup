# Phase 3

## Attack Lab Spec

Phase 3 also involves a code injection attack, but passing a string as argument.
Within the file ctarget there is code for functions hexmatch and touch3 having the following C
representations:
```
/* Compare string to hex represention of unsigned value */
int hexmatch(unsigned val, char *sval)
{
  char cbuf\[110];
  /* Make position of check string unpredictable */
  char *s = cbuf + random() % 100;
  sprintf(s, "%.8x", val);
  return strncmp(sval, s, 9) == 0;
}

void touch3(char *sval)
{
  vlevel = 3; /* Part of validation protocol */
  if (hexmatch(cookie, sval)) {
    printf("Touch3!: You called touch3(\"%s\")\n", sval);
    validate(3);
  } else {
    printf("Misfire: You called touch3(\"%s\")\n", sval);
    fail(3);
  }
  exit(0);
}
```
Your task is to get `CTARGET` to execute the code for `touch3` rather than returning to `test`. You must
make it appear to `touch3` as if you have passed a string representation of your cookie as its argument.

**Some Advice:**

• You will need to include a string representation of your cookie in your exploit string. The string should consist of the eight hexadecimal digits (ordered from most to least significant)
without a leading “0x.”  
• Recall that a string is represented in C as a sequence of bytes followed by a byte with value 0. Type “man ascii” on any Linux machine to see the byte representations of the characters you need.  
• Your injected code should set register %rdi to the address of this string.  
• When functions hexmatch and strncmp are called, they push data onto the stack, overwriting portions of memory that held the buffer used by getbuf. As a result, you will need to be careful where
you place the string representation of your cookie.

Among other things the following image was provided. It is also useful to note that c3 is the hex encoding for the ret instruction.
![image](https://github.com/Motik7/AttackLab-Writeup/assets/60900283/5eb247a9-f732-44bc-9ae4-75f597f749e4)

## Analysis

It's clear that we need to get to `touc32` from `getbuf`. Looking at `getbuf` in cobjectdum we see the following code:  
```
00000000004017be <getbuf>:                        
4017be:	48 83 ec 18          	sub    $0x18,%rsp     
4017c2:	48 89 e7             	mov    %rsp,%rdi      
4017c5:	e8 30 02 00 00       	callq  4019fa <Gets>  
4017ca:	b8 01 00 00 00       	mov    $0x1,%eax      
4017cf:	48 83 c4 18          	add    $0x18,%rsp     
4017d3:	c3                   	retq                
```

Looking at the code, we see the following things happen. We put 0x18 bytes of storage on the stack, and then put our stack pointer into `%rdi`. The function `Gets` is then called which we can assume
inputs whatever we enter into the stack. This opens up the opportunity for code injection. For phase 3, this is injecting our cookie as a string into `%rdi` and then calling `touch3`. Therefore, if we can inject 0x18 bytes of random values and then the address of `touch3` when `retq` attempts to return to the address pointed to by rsp, it'll be our address. Looking again through the object dumb for `touch3` we see  
`00000000004018d4 <touch3>`  
which tells us that our `touch3` function is at address 0x401800. We remember that x86-64 operates on little endian, and thus in our string the address must be formatted correctly.

However, before we can enter `touch3` we first must put our cookie as a string into register `%rdi`. To do this, we'll have to take our return address into some code that we'll write to put the cookie into `%rdi`. We can accomplish this by writing code within the 0x18 initial string bytes, and then returning within it which will begin running the code. However, we need to know where that is. To accomplish that goal, we'll use GDB on ctarget. 

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
This also does not work but for a different reason. A string is just a pointer to a certain area of memory that contains the string. Therefore, `%rdi` needs to hold a memory address, not our actual string. To accomplish this I put the string later in the buffer and then did some hex math to figure out where it is in memory. I then converted the cookie into hex since that's what `hexmatch` wants yielding a final result of  
`5f c3 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 a8 24 64 55 00 00 00 00 e0 24 64 55 00 00 00 00 d4 18 40 00 00 00 00 00 00 00 00 00 00 00 00 00 33 32 62 66 33 66 63 32 00 00 00 00`
