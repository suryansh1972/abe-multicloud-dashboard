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

A secure file encryption system using Ciphertext-Policy Attribute-Based Encryption (CP-ABE). This system allows you to encrypt files with specific access policies, ensuring that only users with the required attributes can decrypt them.

## Features

- Modern, dark-themed UI
- Docker support for easy deployment
- Attribute-based access control
- Support for any file type
- Secure encryption using CP-ABE
- Progress tracking for file operations

## Prerequisites

- Docker installed on your system
- Git (for cloning the repository)
- At least 2GB of free RAM (for PBC library compilation)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/abe-multicloud-dashboard.git
cd abe-multicloud-dashboard
```

2. Build the Docker image:
```bash
docker build -t cp-abe-app .
```

## Running the Application

1. Start the container:
```bash
docker run -d -p 5001:5000 \
  -v $(pwd)/uploads:/app/uploads \
  -v $(pwd)/decrypted:/app/decrypted \
  -v $(pwd)/abe:/app/abe \
  cp-abe-app
```

2. Access the application:
   - Open your web browser
   - Go to: http://localhost:5001

## Using the Application

### Encrypting Files

1. Go to the "Encrypt File" section
2. Click "Choose a file" or drag and drop your file
3. Enter the access policy in the format:
   - For AND conditions: `attribute1 AND attribute2`
   - For OR conditions: `attribute1 OR attribute2`
   - Example: `admin AND finance` (requires both attributes)
4. Click "Encrypt File"
5. The encrypted file will be saved in the `uploads` directory

### Decrypting Files

1. Go to the "Decrypt File" section
2. Upload the encrypted file
3. Enter your attributes (comma-separated)
   - Example: `admin, finance`
4. Click "Decrypt File"
5. The decrypted file will be saved in the `decrypted` directory

## Access Policy Examples

1. Simple AND policy:
   ```
   admin AND finance
   ```
   - Only users with both "admin" AND "finance" attributes can decrypt

2. Simple OR policy:
   ```
   admin OR finance
   ```
   - Users with either "admin" OR "finance" attribute can decrypt

3. Complex policy:
   ```
   (admin AND finance) OR (hr AND manager)
   ```
   - Users must have either:
     - Both "admin" AND "finance" attributes, OR
     - Both "hr" AND "manager" attributes

## Directory Structure

```
abe-multicloud-dashboard/
├── abe/               # CP-ABE implementation
│   └── keys/         # Master keys storage
├── uploads/          # Encrypted files
├── decrypted/        # Decrypted files
├── templates/        # HTML templates
├── app.py           # Main application
├── requirements.txt # Python dependencies
└── Dockerfile       # Docker configuration
```

## Troubleshooting

1. **Port already in use**:
   - If you see "Ports are not available" error, try using a different port:
   ```bash
   docker run -d -p 5002:5000 ...  # Change 5001 to 5002
   ```

2. **Permission issues**:
   - If you encounter permission errors with the mounted volumes, try:
   ```bash
   chmod -R 777 uploads decrypted abe/keys
   ```

3. **Docker build fails**:
   - Ensure you have enough RAM (at least 2GB free)
   - Check your internet connection
   - Try cleaning Docker cache:
   ```bash
   docker system prune -a
   ```

## Security Notes

- The master keys are stored in `abe/keys/`
- Keep these keys secure and never share them
- The encrypted files are stored in `uploads/`
- Decrypted files are stored in `decrypted/`
- Consider using a secure method to distribute attributes to users

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

