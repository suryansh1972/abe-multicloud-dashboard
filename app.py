from flask import Flask, render_template, request, send_file, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from abe.cpabe_utils import setup, encrypt_file, decrypt_file

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DECRYPTED_FOLDER'] = 'decrypted'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure upload and decrypted directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['DECRYPTED_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get attributes from form
        attributes = request.form.get('attributes', '').split(',')
        attributes = [attr.strip() for attr in attributes if attr.strip()]
        
        # Encrypt the file
        try:
            encrypted_file = encrypt_file(file_path, attributes)
            flash('File encrypted successfully!')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error during encryption: {str(e)}')
            return redirect(url_for('index'))

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    
    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Get user attributes from form
        user_attributes = request.form.get('user_attributes', '').split(',')
        user_attributes = [attr.strip() for attr in user_attributes if attr.strip()]
        
        try:
            decrypted_file = decrypt_file(file_path, user_attributes)
            return send_file(decrypted_file, as_attachment=True)
        except Exception as e:
            flash(f'Error during decryption: {str(e)}')
            return redirect(url_for('index'))

if __name__ == '__main__':
    # Initialize CP-ABE setup
    setup()
    app.run(debug=True)
