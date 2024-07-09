**cryptMove_artifacts**

Welcome to the cryptMove_artifacts repository! This project provides the necessary artifacts and resources for the cryptMove. 

**Prerequisites**

Before you begin, ensure you have met the following requirements:
1. Install angr, angrutils
2. Install WinDBG (v1.2402.24001.0)

**Analyze an application**

If you are analyzing an application that has multiple executable files, such as DLLs and EXEs, you have to first find the binary files that implement the cryptographic functions. To find the binaries run `python crypt_binary_finder.py {path to binary}`. This will list the files where crypto constants can be found.

**Continue...**
