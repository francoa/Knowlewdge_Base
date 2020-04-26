FROM THIS [VIDEO]{https://www.youtube.com/watch?v=jtLQ8SzfrDU}
 
First, what's the difference between signing and encryption? In encryption, the sender uses the receivers public key to encrypt the data they want to send, so that only the reciever will be able to read that. In signing, the sender uses it's private key to write a signature in the message, and the reciever uses the sender's public key to read that signature and verify that it actually comes from the expected sender.

We need to validate the boot sequence. Everything is based on digital signature verification. The first element of the process validates the second, and so on. This is called a chain of trust.

ROM -> BootLoader -> kernel -> rootfs

ROM code - Root of trust. Specific to the SoC, to the vendor. Need to store the public key somewhere accessible to the ROM code, on a non-volatile memory. One-Time-Programmable (OTP) fuses. It's better to store the hash of the public key rather than the whole key, then compare the hash with the hash of the public key embedded in a given binary. It's also good to store several public keys, so as to be able to revoque public keys when they are leaked. So then you only need to sign your bootloader with the key, and flash it. The ROM code will authenticate the bootloader and let it run in a secure space.

The bootloader then needs to authenticate the kernel. Disable console in bootloader (if any). Do not trust anything in the environment variables (actually, anything that hasn't been authenticated by the ROM code).
With mkimage:
- openssl genrsa -out my_key.key 4096
- openssl req -batch -new -x509 -key my_key.key -out my_key.crt 






From this [Webinar]{https://www.beningo.com/webinar-secure-bootloader-design-techniques-for-mcus/}

He uses NUCLEO-L476RG and ARM Keil.

Why we need secure boot loader? 
There are 3 types of attack categories:
- Logical: remote exploitation of the device. Maybe open ports, software bugs, gaining access to debug interface, etc.
- Board-level: side-channel attack, memory probing
- Chip-level: laser, physical delayering
As going down, the expertise needed is higher and the cost of attacking the device is also higher. So we need to weigh that related to how critical our application is. 
What features does a secure bootlader have?
- Authenticity for the device: unique and immutable identity. The device identity cannot be changed. This will prevent counterfeiting and protect certificates
- Data confidentiality: protect our IP, protect our keys to communicate to the servers (e.g cloud), protect customers data
- Firmware integrity: code integrity, isolate secure and non-secure processes, secure communications. A secure boot process allows us to ensure this
- Device integrity: tamper prevention. Physical tampering

Two things to think about
- Secure boot: basically ensuring a chain of trust. Also, secure boot code needs to be totally immutable
- Secure firmware updates

X-CUBE-SBSFU (secure boot, secure firmware update):
- Secure boot: offers root of trust. Check authentication and integrity of user application before execution.
- Allows us to encrypt firmware and pass it via USART
- FW installation management: detects new encrypted FW version to install, manage firmware version, rollback, etc.

What kind of encryption are we using? 
The X-CUBE provides 3 schemes: Asymmetric with AES encryption, Asymettric without encryption, Symmetric (AES GCM).

The SBSFU uses several security features from STM32 series:
- Debug Access Port
- RESET Register
- FLASH Mass Erase
- Tamper Pins
- Crypto Library Support
- Memory Protection Unit (MPU)
- FLASH RDP
- TRNG (True Random Number Generator)
- FLASH PCROP
- Firewall (Generates a secure enclave)
- SRAM RDP

The User application will also have to act to ensure a secure device, not only the SBSFU and Secure Engine Middleware.

My secure bootloader has to be a one-off. I wouldn't want to need to change it, ever.

Firmware Image Programming: Single Image Mode of Operation. Dual Image Mode of Operation: Divide slot of memory to have more than one. The active area and a back-up area, for example

First: choose cryptographic scheme, which means choosing your SECoreBin flavor (se_core_crypto_config.h)

The chain of trust is here in this way:
Hardware MCU Security Features -> Cryptographic libraries -> SBSFU (immutable so far)-> User application

Types of protections:
- Static protections: controlled by Option Bytes
- Runtime protections: must be probrammed at each reset. E.g. setting the MPU, controlling the code to be executed, system monitors, creating a secure enclave.

RDP-L2: Disable external access, protects boot options, lock option bytes: WRP, PCROP
WRP PCROP: Protects trusted code, protects part of flash
MPU
Firewall
Crypto
User Application


Zero SRAM before disabling MPU and jumping to user app.

SBSFU prints via serial

Best practices:
- security design should start very very early
- Always lock the flash security bits to protect the bootloader and application
- Securely store private keys: secure enclave memory area
-
 



View [this]{https://www.youtube.com/watch?v=JmFBW-_p2eg&list=PLnMKNibPkDnG4WDZR-Zf3m2DRue8YIibS&index=3}


The Secure Boot (Root of Trust services) is an immutable code, always executed after aystem reset, that checks STM32 static protections, activates STM32 runtime protections and then verifies the authenticity and integrity of user application code before every execution in order to ensure that invalid or malicious code cannot be run.

The Secure Firmware Update application receives the firmware image via a UART interface with the Ymodem protocol, checks its authenticity, and checks the integrity of the code before installing it. The firmware update is done on the complete firmware image, or only on a portion of the firmware image. Examples are provided for single firmware image configuration in order to maximize firmware image size, and for dual firmware image configuration in order to ensure safe image installation and enable over-the-air firmware update capability commonly used in IoT devices. Examples can be configured to use asymmetric or symmetric cryptographic schemes with or without firmware encryption.

The secure key management services provide cryptographic services to the user application through the PKCS #11 APIs (KEY ID-based APIs) that are executed inside a protected and isolated environment. User application keys are stored in the protected and isolated environment for their secured update: authenticity check, data decryption and data integrity check.

STSAFE-A100 is a tamper-resistant secure element (HW Common Criteria EAL5+ certified) used to host X509 certificates and keys, and perform verifications that are used for firmware image authentication during Secure Boot and Secure Firmware Update procedures.

SEE PDF 

The default cryptographic scheme demonstrates ECDSA asymmetric cryptography for firmware verification and AES-CBC symmetric cryptography for firmware decryption. Thanks to asymmetric cryptography, the firmware verification can be performed with publickey operations so that no secret information is required in the device



Secure software coding techniques such as doubling critical tests, doubling critical actions, checking parameters values, and testing a flow control mechanism, are implemented to resist basic fault-injection attacks.

The security strategy is based on the following concepts:
• Ensure single-entry point at reset: force code execution to start with Secure Boot code
• Make SBSFU code and SBSFU secrets immutable: no possibility to modify or alter them once security is fully activated
• Create a protected enclave isolated from SBSFU application and from User applications to store secrets such as keys, and to run critical operations such as cryptographic algorithms
• Limit surface execution to SBSFU code during SBSFU application execution
• Remove JTAG access to the device
• Monitor the system: intrusion detection and SBSFU execution time


Caution - RDP level 1 is not proposed for the following reasons:
1. Secure Boot / Root of Trust (single entry point and immutable code) cannot be ensured, because Option bytes (WRP) can be modified in RDP L1.
2. Device internal flash can be fully reprogrammed (after flash mass erase via RDP L0 regression) with a new FW without any security.
3. Secrets in RAM memory protected by firewall can be accessed by attaching the debugger via the JTAG HW interface on a system reset.


--- See what we don't have in STM32F7

Need to install another IDE

Protected code and data are accessible through a single entry point (call gate mechanism) and it is therefore not possible to run or access any SE code or data withoutpassing through it, otherwise a system reset is generated (refer to Appendix A to get details about call gate mechanism).
Note: Secure Engine critical operations can be extended with other functions depending on user application needs. Only trusted code is to be added to the Secure Engine environment because it has access to the secrets


