# ELF Loader

## Overview

This project was originally developed as a homework assignment for the Operating Systems course I took last year. I decided to make the repository public to showcase some of the low-level programming concepts I worked with, particularly virtual memory and executable loading.

The goal of the assignment was to implement a minimal ELF loader capable of loading executable files into memory and transferring execution to them.

## Implementation

Working on this project helped me understand several concepts related to how executable files are loaded and prepared for execution, such as:

- Validating ELF files by inspecting their headers.
- Using ELF headers to handle different executable types (non-PIE and PIE).
- Mapping executable segments into virtual memory using `mmap()` and setting the appropriate memory permissions using `mprotect()`.
- Handling load addresses and entry points for PIE executables while ensuring memory mappings are page-aligned.
- Allocating and setting up a custom stack, including the required arguments, environment variables, and auxiliary vector.
- Using x86-64 inline assembly to transfer control to the loaded program by setting the new stack pointer and jumping to its entry point.