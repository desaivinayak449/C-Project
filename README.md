🔐 Security App Build
This is a basic cybersecurity application written in C, demonstrating three core security functions:

AES Encryption using OpenSSL

File Integrity Check using libgcrypt

Secure Network Communication using OpenSSL's SSL module

⚠️ Note: This code is educational and not production-ready.
📂 File: pro.c
🔒 AES Encryption
Encrypts plaintext using AES-128:

void encryptData(char *data, int length);
🧾 File Integrity Check
Calculates SHA-256 hash of a file:


void checkFileIntegrity(char *filename);
🌐 SSL/TLS Network Communication
Creates a secure TLS connection to a server:

void secureNetworkCommunication();
⚙️ Requirements
Install required libraries before building:

#For Linux System Installation

sudo apt update
sudo apt install libssl-dev libgcrypt-dev


🛠️ Compilation
Use GCC to compile the program:

# For Run This Code For Linux User
gcc -o security_app pro.c -lssl -lcrypto -lgcrypt


🚀 Sample Usage
Modify main() in pro.c like this:

int main() {
    char data[] = "SensitiveData1234";
    encryptData(data, strlen(data));

    checkFileIntegrity("sample.txt");

    secureNetworkCommunication();

    return 0;
}
