# UltimateDRM

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Version](https://img.shields.io/badge/1.0-999999?style=flat-square&logo=Version&label=Version&labelColor=333333)

DRM Library for Windows (x64) in C++  

This project is an anti-tamper & anti-debugging static library for Windows. It uses the PIMPL idiom to hide implementation details so that it can be added into other projects without revealing methods. It's currently in a working state, with licensing mostly finished (just needs online checking to be added, offline checks are working). All protections/checks are runtime, and perhaps in the future we will add post-build packing /w a unpacking launcher.  

Anyone is free to contribute as long as PRs are quality and follow the same code style. The project is currently being supported for Visual Studio 17 (2022), CMake support will be added in the future.  

** This project was started on July 19, 2025, and might not have many files yet  
** There is no such thing as an 'uncrackable DRM' - any code or binaries run on a client machine can be tampered with enough effort  

## Current Features:  
- Settings class which controls which types of DRM checks to occur, and resides in protected memory    
- Memory protections/anti-tamper     
- IAT hook checks on all loaded modules  
- Licensing (offline license checking currently working)  
- Periodic Integrity checks on all non-writable sections of all loaded modules  
- Blocks multiple client instances   
- Checks for and blocks threads spawning on addresses outside of any loaded module (<Windows 10 only)  
- Checks the parent process against a whitelist   
- Optionally enforces code signing via Authenticode APIs  
- Anti-debugging checks and hiding threads from debuggers   
- Very low CPU & RAM usage    
- Supports both x86 and x64  

## How to use:  
The project is a static library (.lib) which you can include in your C++ project, along with the `UltimateDRM.hpp` header file. You can then create a `UltimateDRM` class object and call the `Protect` function. Please see `DRMTest/DRMTest.cpp` for an example of how to implement this into your own project.  

## Testing
The `DRMTest` folder contains a project which links to `UltimateDRM.lib` and tests different features of it. A failed test returns non-zero from its `main` function, while a successful test returns 0.  

GitHub Actions is being used to conduct automated tests, and will trigger each time a code push is done. So far this is just a simple build + run workflow.  

## Licensing
Anyone is free to use this project. If you end up using it in a project that is for commercial purposes and makes money, credits would be appreciated at the least.  

## Example Output
<img width="721" height="161" alt="image" src="https://github.com/user-attachments/assets/5ab7c7e2-d4b7-40f1-8178-7bb9056444cf" />

