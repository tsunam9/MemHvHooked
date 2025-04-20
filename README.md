<p align="center">
    <img width="100px" height="auto" src="assets/chip-icon.png" />
    <h3 align="center">memhv-Hook</h3>
    <p align="center"><i>Minimalistic hypervisor with introspection and stealth hook capabilities</i></p>
</p>

## About
This project is forked from MemHv and adds stealth hook capabilities. 

## Explination of the algorithm

NPT doesnt support execute only pages so we have to use a workaround. 
We use a feature in AMD cpu's called [Memory Protection Keys](https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/programmer-references/24593.pdf) (Pg.164)
By protecting the page of the function we want to hook. Any read or write access is interrupted by the Hypervisor. but this does not apply to instruction fetches. This effectively creates an execute only page with AMD-V

We place the hook by replacing the first byte of the function with and INT3 instruction causing a VMEXIT, allowing us to change the RIP to our handler function and resume the guest os.

If the guest os attempts to read or write to the function, we restore the first instruction of the function, single step the guest os to complete the read or write, then set it back.


![screenshot](assets/screenshot.png)

## Support
- Windows 10 or Windows 11 (both 64-bit, tested on 22H2 and 24H2)
- AMD processor with SVM and NPT support

## Usage
1. Ensure that you have SVM enabled in UEFI firmware options (BIOS)
2. Make sure Microsoft Hyper-V is fully disabled
3. Sign and load the driver or use other means to load it ([kdmapper](https://github.com/TheCruZ/kdmapper), [KDU](https://github.com/hfiref0x/KDU), **make sure PE headers are not erased** if you want the hypervisor to use NPT to hide its memory from guest)
4. Enjoy hypercall API (see client folder)

## Detection vectors
Common timing attacks are ineffective against this hypervisor, as it does not exit on CPUID or similar instructions typically used in such attacks. Memory of the hypervisor is hidden from the guest using NPT.
Detection of Cr4.PKE bit being set is possible. A way to negate this is to virtualize all cr4 reads and writes to protect the PKE bit.

## Credits
- [SimpleSvm](https://github.com/tandasat/SimpleSvm) by @tandasat
