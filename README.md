# UltimateDRM

![C++](https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Visual Studio](https://img.shields.io/badge/Visual%20Studio-5C2D91.svg?style=for-the-badge&logo=visual-studio&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Version](https://img.shields.io/badge/1.0-999999?style=flat-square&logo=Version&label=Version&labelColor=333333)

DRM Library for Windows (x64) in C++  

This project aims to take the good portions of the UltimateAnticheat project while improving aspects which were messy or implemented poorly, such as the integrity checker. An emphasis will be made on code readability, modularity, and reusability for the core aspects of this DRM. Anyone is free to contribute as long as PRs are quality and follow the same code style. The project is currently being supported for Visual Studio 17 (2022), CMake support will be added in the future.  

** This project was started on July 19, 2025, and might not have many files yet  
** There is no such thing as an 'uncrackable DRM' - any code or binaries run on a client machine can be tampered with enough effort  

## Features:  
- Memory protections  
- Licensing  (not yet finished)  
- Integrity checks (periodic checksums, loaded module checks)  
- Blocks multiple client instances  

## How to use:  
The project is a static library (.lib) which you can include in your C++ project, along with the `DRM.hpp` header file. You can then create a `DRM` class object and call the `Protect` function. Please see `DRMTest/DRMTest.cpp` for an example of how to implement this into your own project.  

## Testing
The `DRMTest` folder contains a project which links to `UltimateDRM.lib` and tests different features of it. A failed test returns -1 from its `main` function, while a successful test returns 0.  

## Licensing
Anyone is free to use this project. If you end up using it in a project that is for commercial purposes and makes money, credits would be appreciated at the least.  
