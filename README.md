# AttackLab-Writeup
Attack Lab Writeup for UCLA's CS33 Introduction to Computer Organization Course

## Introduction
The Attack Lab is a demonstration of potential binary exploitation using code injection and ROP attacks. The Attack Lab is separated into 4 phases. The first two are code injection attacks, and the last two are ROP attacks. As of now, I have completed only the first three phases. The last one will be done sometime later. The spec for this assignment is provided in attack_lab_spec.pdf

## Target801
Target801 contains the attack lab code along with solutions. ctarget is a binary of the code to be attacked with code injection. cobjectdum is the object dump of ctarget. Solutions are of the form `sol\[\[:digit:\]\]\*.txt`. solraw is a file created by running a solution against hex2raw to generate the necessary input for the exploit; it may be removed in a future commit. cookie.txt holds the cookie that may be required for certain phases of the attacklab. farm.c contains code that may be used for ROP attacks. rtarget is a binary of the code to be attacked with return oriented programming (ROP) attacks. robjectdum holds the object dump of rtarget.
