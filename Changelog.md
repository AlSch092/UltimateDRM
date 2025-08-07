# Changelog - UltimateDRM  

- Aug 6 2025: Added IAT hook checks for all loaded modules  
- Aug 5 2025:  Finished integrity checks on all non-writable sections of all modules  
- Aug 3 2025:  Added x86 support, integrity checks on all loaded modules  
- Aug 1 2025:   Added checks for if pages are writable in .text, .rdata  
- July 31 2025: Fixed checksum integrity checks, added disk check to periodic checks, all working now  
- July 30 2025: Improved integrity checker code, added checks for multiple sections, added routine for checking file on disc  
- July 25 2025: Add hypervisor checks, add DRMExceptions class, clean up Process class  
- July 24 2025: Added blocking unknown threads via TLS callbacks, anti-debug code  
- July 22 2025: Added blocking of multiple process instances  
- July 21 2025: Added TLS callbacks, vectored exception handler, start of licensing code  
- July 20 2025: Added module checksums, periodic checksum comparisons    
- July 19 2025: Added code signing checks, PIMPL idiom for safe static .lib usage  
- July 18 2025: First commit. Added section remapping.  