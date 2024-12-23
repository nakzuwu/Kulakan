from flask import render_template, request, redirect, url_for, session, flash, current_app, jsonify
from models.user import User
from models.toko_detail import TokoDetail
from models.product import Product
from models import db
from form import ProfileForm
import os
import uuid


ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_user_from_session():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        return user
    return None

def menuproduk():
    dataProduk = Product.query.all()
    return render_template('frontend/menuproduk.html', dataProduk=dataProduk)

def detailProduk(id):
    dataBs = Product.query.get_or_404(id)
    return render_template('frontend/detailproduk.html', dataBs=dataBs)

def home():
    user = get_user_from_session()
    if user:
        reviews = session.get('reviews', []) 
        return render_template('index.html', user=user, reviews=reviews)
    return redirect(url_for('login'))

def add_review():
    review_text = request.form.get('reviewText')
    if not review_text:
        return jsonify({'error': 'Review text is required'}), 400
    
    reviews = session.get('reviews', [])
    reviews.append({"text": review_text})
    session['reviews'] = reviews
    
    return jsonify({"text": review_text})

def daftar_toko():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        # Ambil data dari form
        name = request.form['nama']
        address = request.form['alamat']
        no_hp = request.form['no_hp']
        bank = request.form['bank']
        no_rek = request.form['no_rek']
        
        # Update data user (name dan address)
        user.name = name
        user.address = address
        db.session.commit()  # Simpan perubahan ke tabel User
        
        # Buat entri baru untuk TokoDetail
        toko_detail = TokoDetail(user_id=user.id, no_hp=no_hp, bank=bank, no_rek=no_rek, status='Pending')
        db.session.add(toko_detail)
        db.session.commit()

        flash("Pendaftaran toko berhasil, menunggu konfirmasi.", "success")
        return redirect(url_for('dashboard'))  # Halaman setelah berhasil mendaftar
    
    return render_template('frontend/daftartoko.html', user=user)

def profile_settings():
    if 'user_id' not in session:
        flash('You need to log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    form = ProfileForm()

    if form.validate_on_submit():
        # Update user details
        user.name = form.name.data
        user.email = form.email.data
        user.address = form.address.data

        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], filename))

                # Update user's profile_photo in the database
                user.profile_photo = filename

        # Save other updates to the database
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile_settings'))

    # Prepopulate the form with current data
    form.name.data = user.name
    form.email.data = user.email
    form.address.data = user.address

    return render_template('profile_settings.html', form=form, user=user)

def profile_settings_api():
    # Ensure user is logged in (check if user_id is in session)
    if 'user_id' not in session:
        return jsonify({'message': 'You need to log in first.'}), 403

    # Get user from the database using the user_id from session
    user = User.query.get(session['user_id'])

    if not user:
        return jsonify({'message': 'User not found.'}), 404

    if request.method == 'GET':
        # Return current profile data as JSON
        return jsonify({
            'name': user.name,
            'email': user.email,
            'address': user.address,
            'profile_photo': user.profile_photo or None
        })

    if request.method == 'POST':
        # Get the data from the request body (JSON)
        name = request.json.get('name')
        email = request.json.get('email')
        address = request.json.get('address')

        # Update user details
        if name:
            user.name = name
        if email:
            user.email = email
        if address:
            user.address = address

        # Handle profile photo upload (if any)
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                # Generate a unique filename using UUID
                ext = file.filename.rsplit('.', 1)[1].lower()  # Get file extension
                filename = f"{uuid.uuid4().hex}.{ext}"  # Create unique filename
                filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # Update user's profile_photo in the database
                user.profile_photo = filename

        # Commit changes to the database
        db.session.commit()

        return jsonify({'message': 'Profile updated successfully!'}), 200