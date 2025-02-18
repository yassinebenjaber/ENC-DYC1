# Encryption Software Application

## Description  
This Python-based application provides encryption and decryption capabilities for text and files using the Advanced Encryption Standard (AES) and Triple Data Encryption Standard (DES3) algorithms. It ensures data confidentiality by transforming readable information into an unreadable format, which can only be reversed with the correct key.  

The application includes:  
- **Text and File Encryption/Decryption**: Encrypts and decrypts both text inputs and file contents.  
- **Algorithm Selection**: Supports AES (128/256-bit) and DES3 encryption methods.  
- **Security Testing**: Implements brute force and sensitivity tests to assess encryption strength.  

## Core Features  

1. **Encryption/Decryption**:  
   - Accepts user input (text or file) and encrypts it with a selected algorithm.  
   - Decrypts encrypted data using the correct key.  

2. **Algorithm Selection**:  
   - **AES (Advanced Encryption Standard)**: Symmetric encryption with variable key sizes (128, 192, or 256 bits).  
   - **DES3 (Triple DES)**: Triple-layer encryption for improved security over standard DES.  

3. **Security Tests**:  
   - **Brute Force Test**: Simulates brute force attacks to evaluate key strength and algorithm resilience.  
   - **Sensitivity Test**: Demonstrates the avalanche effect by measuring the impact of minor input changes on the encrypted output.  

4. **File Handling**:  
   - Encrypts files of any type, with secure key management.  
   - Handles large files efficiently without performance degradation.  

## Technical Details  

- **Key Generation**:  
  - AES: 128-bit or 256-bit keys generated with secure random functions.  
  - DES3: 168-bit keys derived using the Python `Crypto` library.  

- **Padding and Integrity**:  
  - Uses PKCS#7 padding for text input to meet block size requirements.  
  - Verifies input integrity during decryption to detect potential tampering.  

- **Test Implementation**:  
  - Brute force tests iterate through possible keys within a constrained range to simulate real-world attack scenarios.  
  - Sensitivity tests compare outputs generated from inputs that differ by a single bit, demonstrating encryption robustness.  

## Technologies Used  

- **Python**: Application logic, encryption operations, and testing implementations.  
- **Cryptography Library**: Handles AES and DES3 encryption.  

## Environment  

- **Operating System**: Windows 10.  
- **Development Environment**: Visual Studio Code.  

## Use Cases  

- Protecting sensitive text and file-based information.  
- Demonstrating encryption algorithm behavior for educational or testing purposes.  
- Testing encryption resilience against brute force and input variation attacks.  

This application provides a practical, secure, and scalable solution for encrypting and decrypting data, while also offering insight into the strength of different encryption algorithms.  




<h2>Program walk-through:</h2>

<p align="center">
 <br/>
<img src="https://imgur.com/72C93ml.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<p align="center" >
<br/>
 <img src="https://imgur.com/vwDJVej.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<br/>
 <img src="https://imgur.com/i1JtGIp.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<br/>
 <img src="https://imgur.com/V3fBeux.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />

</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
