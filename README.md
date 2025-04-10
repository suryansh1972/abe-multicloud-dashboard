

```markdown
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

