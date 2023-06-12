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
