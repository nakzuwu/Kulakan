from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response, send_from_directory
from flask_session import Session
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from form import ProfileForm
from models import db
from models.user import User
from models.product import Product
from werkzeug.security import generate_password_hash, check_password_hash
from models.toko_detail import TokoDetail
from dotenv import load_dotenv
from controllers import user_controller
from controllers import auth_controller
from controllers import admin_controller
from controllers import superadmin_controller
from controllers import checkout_controller
from controllers import chatbotController
import tensorflow as tf
from tensorflow.keras.preprocessing.image import load_img, img_to_array
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image
import numpy as np
import numpy as np
import os
import jwt
from flask_cors import CORS

app = Flask(__name__)
app.secret_key = 'capstonekel7' 

model = load_model('sembako.h5')
CORS(app) 

s = URLSafeTimedSerializer(app.secret_key)

load_dotenv()

# Access environment variables
UPLOAD_FOLDER = os.getenv('UPLOAD_FOLDER')
ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

# Other configurations
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIxONS'] = os.getenv('SQLALCHEMY_TRACK_MODIFICATIONS') == 'True'
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['SESSION_TYPE'] = 'filesystem'  # Use file system to store sessions
app.config['SESSION_PERMANENT'] = False    # Sessions are not permanent
app.config['SESSION_USE_SIGNER'] = True    # Use a signed session cookie
app.config['SESSION_KEY_PREFIX'] = 'myapp_'  # Prefix for session keys
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires in 1 hour
Session(app)

mail = Mail(app)

db.init_app(app)
with app.app_context():
    db.create_all()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check if user is logged in
            if 'user_id' not in session:
                flash("You need to log in to access this page.", "warning")
                return redirect(url_for('login'))
            
            # Fetch the user object (adjust based on your user model)
            user = User.query.get(session['user_id'])
            if not user or user.role != role:
                flash("You do not have permission to access this page.", "danger")
                return   redirect(url_for('home'))
            
            return func(*args, **kwargs)
        return wrapper
    return decorator

def predict_label(img_path):
    # Memuat gambar dan menyesuaikan ukurannya
    i = image.load_img(img_path, target_size=(128, 128))
    i = image.img_to_array(i) / 255.0  # Normalisasi pixel
    i = i.reshape(1, 128, 128, 3)  # Mengubah bentuk agar sesuai dengan model
    # Melakukan prediksi dengan model
    p = model.predict(i)
    # Mendapatkan indeks kelas dengan probabilitas tertinggi
    predicted_class_index = np.argmax(p, axis=1)[0]
    # Mengembalikan label kelas dan deskripsi berdasarkan indeks
    return dic[predicted_class_index]

@app.route("/submit", methods=['GET', 'POST'])
def get_output():
    if request.method == 'POST':
        img = request.files['my_image']
        img_path = "static/uploads/" + img.filename
        img.save(img_path)
        # Memanggil fungsi prediksi dan menyimpan hasilnya
        result = predict_label(img_path)
        label = result['label']
        description = result['description']
        # Merender kembali template dengan hasil prediksi dan deskripsi
        return render_template("/frontend/scan.html", prediction=label, description=description, img_path=img_path)
    
@app.errorhandler(404)
def page_not_found(e):
    return jsonify({'status': 'error', 'message': 'Endpoint tidak ditemukan'}), 404

#Page

@app.route('/')
def home():
    return user_controller.home()

@app.route('/add_review', methods=['POST'])
def add_review():
    return user_controller.add_review()

@app.route('/profile_settings', methods=['GET', 'POST'])
def profile_settings():
    return user_controller.profile_settings()

@app.route('/daftartoko', methods=['GET', 'POST'])
@role_required('user')
def daftar_toko():
    return user_controller.daftar_toko()

@app.route('/detailproduk/<int:id>')
def detailProduk(id):
    return user_controller.detailProduk(id)

@app.route('/menuproduk')
def menuproduk():
    return user_controller.menuproduk()

@app.route('/toko')
def toko():
    return render_template('/frontend/toko.html')

@app.route('/setting')
def setting():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('frontend/setting.html', user=user)

@app.route('/tentang')
def tentang():
    return render_template('/settings/tentang.html')

@app.route('/scan')
def scan():
    return render_template('frontend/scan.html')

@app.route('/keranjang', methods=['GET', 'POST'])
def keranjang():
    return checkout_controller.keranjang()

@app.route('/add_to_cart/<int:product_id>', methods=['POST'])
def add_to_cart(product_id):
    return checkout_controller.add_to_cart(product_id)

@app.route('/update_cart', methods=['POST'])
def update_cart():
    return checkout_controller.update_cart()

@app.route('/process_payment/<float:total>', methods=['GET'])
def process_payment(total):
    return checkout_controller.process_payment(total)

@app.route('/payment', methods=['GET', 'POST'])
def payment():
    return checkout_controller.payment()

@app.route('/riwayat')
def riwayat():
    return render_template('/frontend/riwayat.html')

@app.route('/query', methods=['POST'])
def query():
    return chatbotController.chat()

#auth
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if not user:
            flash('Email tidak ditemukan.', 'danger')
            return redirect(url_for('forgot_password'))

        try:
            # Generate JWT token
            token = jwt.encode(
                {"user_id": user.id, "exp": datetime.utcnow() + timedelta(houFrs=1)},
                app.config['SECRET_KEY'],
                algorithm='HS256'
            )
            reset_url = url_for('reset_password', token=token, _external=True)

            # Send email
            msg = Message('Reset Password', recipients=[email])
            msg.body = f'Klik tautan berikut untuk mereset password Anda: {reset_url}'
            mail.send(msg)  # Use the imported mail object

            flash('Instruksi reset password telah dikirim ke email Anda.', 'info')
        except Exception as e:
            flash(f'Gagal mengirim email: {str(e)}', 'danger')
            app.logger.error(f"Error during email sending: {str(e)}")

        return redirect(url_for('forgot_password'))

    return render_template('auth/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    return auth_controller.reset_password(token)

@app.route('/register', methods=['GET', 'POST'])
def register():
    return auth_controller.register()

@app.route('/login', methods=['GET', 'POST'])
def login():
    return auth_controller.login()

@app.route('/logout')
def logout():
    return auth_controller.logout()

@app.route('/api/register', methods=['POST'])
def registerApi():
    try:
        data = request.get_json()

        # Validasi input
        if not data:
            return jsonify({'message': 'No data provided.', 'status': 'error'}), 400

        name = data.get('name', '').strip()
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        address = data.get('address', None)
        profile_photo = data.get('profile_photo', 'default.jpg')
        role = data.get('role', 'user')  # Default role adalah 'user'

        # Validasi input yang wajib
        if not all([name, email, password]):
            return jsonify({'message': 'Name, Email, and Password are required!', 'status': 'error'}), 400

        # Cek apakah email sudah terdaftar
        if User.query.filter_by(email=email).first():
            return jsonify({'message': 'Email already exists!', 'status': 'error'}), 400

        # Hash password
        hashed_password = generate_password_hash(password)

        # Simpan data user
        user = User(
        name=name,
        email=email,
        password=hashed_password,
        address=address,
        profile_photo=profile_photo,
        role=role
        )

        db.session.add(user)
        db.session.commit()

        # Return response sukses
        return jsonify({
        'message': 'Account created successfully!',
        'status': 'success',
        'user': {
        'id': user.id,
        'name': user.name,
        'email': user.email,
        'address': user.address,
        'profile_photo': user.profile_photo,
        'role': user.role,
        }
        }), 201

    except Exception as e:
        app.logger.error(f"Error during registration: {str(e)}")
        return jsonify({'message': 'An error occurred during registration.', 'status': 'error'}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'error': 'Email and password are required.'}), 400

        user = User.query.filter_by(email=email).first()
        if not user or not check_password_hash(user.password, password):
            return jsonify({'error': 'Invalid email or password.'}), 401

        # Set user session
        session['user_id'] = user.id
        session['user_name'] = user.name
        session['user_role'] = user.role

        response = make_response(jsonify({
            'message': 'Login successful!',
            'role': user.role
        }), 200)
        response.set_cookie('session', session.sid, httponly=True)  # 
        return response

    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'An error occurred during login.'}), 500

@app.route('/detect', methods=['POST'])
def detect():
    CLASS_NAMES = {
    0: "Rayco",
    1: "Beras",
    2: "beras fortune",
    3: "garam daun",
    4: "garam refina",
    5: "gula",
    6: "gula roseband",
    7: "Gulaku",
    8: "indomie",
    9: "Kopi",
    10: "Minyak Bimoli Pouch",
    11: "Minyak Bimoli Pouch3",
    12: "Minyak Sania Pouch",
    13: "Minyak Tropical Pouch",
    14: "pasta gigi pepsodent merah bungkus",
    15: "sabun lifebuoy biru batang",
    16: "susu frisian flag sachet putih",
    17: "susu indomilk sachet",
    18: "Teh 2 tang",
    19: "teh poci",
    20: "tidak kenali"
    }
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'No image selected'}), 400
    
    # Simpan file gambar
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(filepath)
    
    # Preprocessing gambar
    image = load_img(filepath, target_size=(224, 224))  # Sesuaikan dengan input model Anda
    image = img_to_array(image) / 255.0
    image = np.expand_dims(image, axis=0)
    
    # Prediksi dengan model
    predictions = model.predict(image)
    predicted_class = np.argmax(predictions, axis=1)[0]
    predicted_name_text = CLASS_NAMES[predicted_class]  # Ambil nama awalan dari mapping
    
    # Query database berdasarkan nama awalan
    products = Product.query.filter(Product.nama_barang.like(f"{predicted_name_text}%")).all()
    
    product_list = []
    for product in products:
        product_list.append({
            'id': product.id,
            'nama_barang': product.nama_barang,
            'harga': product.harga,
            'gambar': product.gambar
        })
    print("Prediksi nama produk:", predicted_name_text)
    print("Produk ditemukan:")
    for product in products:
        print(product.nama_barang, product.harga, product.gambar)
    return jsonify({'products': product_list})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    return auth_controller.api_logout()

@app.route('/api/profile', methods=['GET'])
def get_user_profile():
    if 'user_id' not in session:
        return jsonify({'message': 'You need to log in first.', 'status': 'error'}), 401

    # Ambil data pengguna berdasarkan user_id dari session
    user = User.query.get(session['user_id'])

    if not user:
        return jsonify({'message': 'User not found.', 'status': 'error'}), 404

    # Buat URL lengkap untuk foto profil
    profile_photo_url = (
        f"{request.url_root}{UPLOAD_FOLDER}/{user.profile_photo}" 
        if user.profile_photo else None
    )

    # Kembalikan semua data profil pengguna
    return jsonify({
        'status': 'success',
        'message': 'User profile fetched successfully.',
        'data': {
            'id': user.id,
            'name': user.name,
            'email': user.email,
            'address': user.address,
            'profile_photo': profile_photo_url
        }
    }), 200


@app.route('/static/profile_photo/<filename>', methods=['GET'])
def get_profile_photo(filename):
    """Mengambil file gambar dari direktori upload."""
    try:
        return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
    except FileNotFoundError:
        return jsonify({'message': 'Profile photo not found.', 'status': 'error'}), 404
    
#admin

@app.route('/admin/dashboard')
@role_required('store_admin')
def dashboard():
    return admin_controller.dashboard()

@app.route('/admin/addproduk', methods=['GET', 'POST'])
@role_required('store_admin')  # Membatasi akses hanya untuk admin
def addproduk():
    return admin_controller.addproduk()

@app.route('/admin/produk', methods=['GET'])
@role_required('store_admin') 
def listProduk():
    return admin_controller.listProduk()

@app.route('/admin/editproduk/<int:id>', methods=['GET', 'POST'])
@role_required('store_admin')
def editProduk(id):
    return admin_controller.editProduk(id)

@app.route('/admin/deleteproduk/<int:id>', methods=['POST'])
@role_required('store_admin')
def deleteProduk(id):
    return admin_controller.deleteProduk(id)

@app.route('/superadmin/listakun', methods=['GET'])
@role_required('super_admin')
def listakun():
    return superadmin_controller.listakun()

@app.route('/superadmin/editakun/<int:id>', methods=['GET', 'POST'])
@role_required('super_admin')
def editakun(id):
    return superadmin_controller.editakun(id)

@app.route('/superadmin/deleteakun/<int:id>', methods=['POST'])
@role_required('super_admin')
def deleteakun(id):
    return superadmin_controller.deleteakun(id)

@app.route('/superadmin/produk', methods=['GET'])
@role_required('super_admin') 
def listallProduk():
    return superadmin_controller.listProduk()

@app.route('/superadmin/sentimen', methods=['GET', 'POST'])
@role_required('super_admin')
def sentimen():
    return superadmin_controller.sentimen()

@app.route('/superadmin/acc', methods=['GET'])
@role_required('super_admin')
def acc_toko():
    return superadmin_controller.acc_toko()

@app.route('/superadmin/approve_toko/<int:toko_id>', methods=['GET'])
@role_required('super_admin')
def approve_toko(toko_id):
    return superadmin_controller.approve_toko(toko_id)

@app.route('/superadmin/reject_toko/<int:toko_id>', methods=['GET'])
@role_required('super_admin')
def reject_toko(toko_id):
    return superadmin_controller.reject_toko(toko_id)

if __name__ == '__main__':
    app.run(debug=True)