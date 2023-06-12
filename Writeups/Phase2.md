# Phase 2

## Attack Lab Spec

Phase 2 involves injecting a small amount of code as part of your exploit string.
Within the file `ctarget` there is code for a function `touch2` having the following C representation:  
`void touch2(unsigned val)                              `   
`{                                                      `  
`  vlevel = 2; /* Part of validation protocol \*/         `  
`  if (val == cookie) {                                   `  
`    printf("Touch2!: You called touch2(0x%.8x)\n", val); `  
`    validate(2);                                         `  
`  } else {                                               `  
`    printf("Misfire: You called touch2(0x%.8x)\n", val); `  
`    fail(2);                                             `  
`  }                                                      `  
`  exit(0);                                               `  
`}                                                      `  
Your task is to get `CTARGET` to execute the code for `touch2` rather than returning to `test`. In this case,
however, you must make it appear to `touch2` as if you have passed your cookie as its argument.  

**Some Advice:**  
• You will want to position a byte representation of the address of your injected code in such a way that `ret` instruction at the end of the code for `getbuf` will transfer control to it.  
• Recall that the first argument to a function is passed in register `%rdi`.  
• Your injected code should set the register to your cookie, and then use a `ret` instruction to transfer control to the first instruction in `touch2`.  
• Do not attempt to use `jmp` or `call` instructions in your exploit code. The encodings of destination addresses for these instructions are difficult to formulate. Use `ret` instructions for all transfers of 
control, even when you are not returning from a call
