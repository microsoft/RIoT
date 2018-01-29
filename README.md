# RIoT Reference Architecture
## Introduction
Robust, Resilient, Recoverable Internet of Things (RIoT), from Microsoft Research, is an architecutre for providing foundational trust serevices to computing devices. RIoT presents a reference implementation for a DICE Architecture that provides cryptographically strong device identity and device attestation.  Together, DICE and RIoT also provide a foundation for device recovery and resiliency ([Cyber Resilient Platform Inititative](https://aka.ms/cyrep)), secure and verifiable updates, data at rest protection (sealing), and a host of other security-critical use cases.

The Device Provisioning Service (DPS) from Azure IoT also takes a dependency on DICE and RIoT for secure device identity and attestation.  The DPS X.509-based protocols rely on the cryptographic keys and certificates produced by RIoT and the Root of Trust for Measurement provided by DICE in hardware.

For more info on DPS from Azure IoT [this](https://docs.microsoft.com/en-us/azure/iot-dps/) is a good place to start.

## The RIoT Repo
The RIoT repository is organized as follows:
 * _Emulator_ -  A software emulator for DICE/RIoT.  The emulator code can be used by developers to simulate inputs to DICE hardware and create RIoT keys and certificates based on those inputs.  The emulator is used during dev/test to provide user-controlled inputs in a more developer-friendly environment.  The DICE/RIoT emulator enables a much faster development cycle than working only with real hardware. 
 * _Reference_ - A simulated DICE/RIoT-based MCU software stack.  The RIoT reference presents a simulated DICE device, the RIoT reference code itself, and very simple device firmware layer.  These three self-contained elementes represent the basic components of a simple DICE-based MCU.  
 * _Pkgs_ - The packages directory contains the metadata and source code for supporting DICE/RIoT development in other languages.  In addition to the C-language reference, DICE/RIoT emulators and tests are also provided in Java (Maven), C# (NuGet), and javascript (npm).
 * _Tools_ - Sources, tools and tests enabling RIoT development and validation.

## What's Next
Soon we will also share demos and sample code for specific DICE-enabled hardware as well.  This will include the STM32L4 family of MCUs from STMicroelectronics, the CEC1702 from Microchip, Authenta-based SPI flash from Micron, and others.

## Contributing
For more information on DICE, and to learn how you can contribute, we encourage you to check out the [DICE Architectures workgroup](https://trustedcomputinggroup.org/work-groups/dice-architectures/) (DiceArch) in the [Trusted Computing Group](https://trustedcomputinggroup.org/).  For questions, comments, or contributions to the RIoT project from MSR, feel free to contact us at riotdev@microsoft.com.

  


