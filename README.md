# 🔐 Attribute-Based Encryption (ABE) for Secure Multi-Cloud Data Sharing


This is the **partial implementation** of a final year major project focused on **Ciphertext-Policy Attribute-Based Encryption (CP-ABE)** to enable secure file sharing between cloud platforms like AWS, Google Cloud, and Azure.

---

## 🚀 Features (Partial Implementation)

- ✅ CP-ABE using the Charm-Crypto library
- ✅ Secure file upload and encryption based on attributes
- ✅ Decryption based on user-provided attributes
- ✅ Bootstrap-powered frontend for usability
- ✅ Flask-based lightweight backend

---

## 🛠️ Tech Stack

- Python 3.x
- Flask 3.0.2
- Charm-Crypto 0.50
- Bootstrap 5
- Werkzeug 3.0.1

---

## 📁 Project Structure

```
.
├── app.py
├── requirements.txt
├── abe/
│   └── cpabe_utils.py
│   └── keys/
├── templates/
│   └── index.html
├── uploads/
├── decrypted/
```

---

## 🧪 How to Run

1. **Install dependencies**

```bash
pip install -r requirements.txt
```

2. **Run the Flask app**

```bash
python app.py
```

3. **Go to your browser**

```
http://localhost:5000
```

---

## 🔐 Encryption Example

- Upload a file
- Provide a policy like:  
  ```
  admin and finance
  ```

## 🔓 Decryption Example

- Upload the encrypted file
- Provide user attributes like:  
  ```
  admin, finance
  ```

---

## 📦 What's Next (Full Implementation)

- Integrate with AWS S3, GCP, and Azure Blob for multi-cloud upload/download  
- Add user login + identity-based access  
- Audit logs, admin panel, and visualization  
- Full dashboard + file sharing controls

---

## 💡 Note

This is the **partial implementation** focused on:
- CP-ABE file encryption/decryption
- Local testing via Flask
- Ready to extend into a multi-cloud system

# CP-ABE File Encryption System

A Flask-based application that implements Ciphertext-Policy Attribute-Based Encryption (CP-ABE) for secure file sharing.

## Prerequisites

- Docker installed on your system
- Git (optional, for cloning the repository)

## Quick Start with Docker

1. Clone the repository (or download the files):
```bash
git clone <repository-url>
cd abe-multicloud-dashboard
```

2. Build the Docker image:
```bash
docker build -t abe-app .
```

3. Run the container:
```bash
docker run -p 5000:5000 -v $(pwd)/uploads:/app/uploads -v $(pwd)/decrypted:/app/decrypted -v $(pwd)/abe/keys:/app/abe/keys abe-app
```

The application will be available at `http://localhost:5000`

## Features

- File encryption with attribute-based access control
- Secure file sharing based on user attributes
- Web-based interface for easy file management

## Usage

1. **Encrypt a File**:
   - Upload a file
   - Specify access policy attributes (comma-separated)
   - Click "Encrypt File"

2. **Decrypt a File**:
   - Upload an encrypted file
   - Provide your attributes
   - Click "Decrypt File"

## Directory Structure

- `uploads/`: Stores encrypted files
- `decrypted/`: Stores decrypted files
- `abe/keys/`: Stores ABE keys and metadata

## Notes

- The Docker container mounts local directories for persistent storage
- Make sure the mounted directories have proper write permissions
- The application uses port 5000 by default

