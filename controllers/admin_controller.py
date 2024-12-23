from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from models.user import User
from models import db
from models.product import Product
from dotenv import load_dotenv
import uuid
import os

ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', 'png,jpg,jpeg,gif').split(','))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to get the current logged-in user from session
def get_user_from_session():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        return user
    return None

# Dashboard for store admin
def dashboard():
    user_id = session.get('user_id')
    admin = User.query.get(user_id)

    if admin and admin.role == 'store_admin':
        products = Product.query.filter_by(user_id=admin.id).all()
        return render_template('admin/content/dashboard.html', admin=admin, products=products)
    
    flash("You do not have permission to access this page.", "danger")
    return redirect(url_for('home'))

# Add new product
def addproduk():
    if request.method == 'POST':
        nama_barang = request.form['nama_barang']
        harga = request.form['harga']
        kategori = request.form['kategori']
        stok = request.form['stok']
        deskripsi = request.form['deskripsi']

        # Handling file upload for image
        if 'gambar' in request.files:
            file = request.files['gambar']
            if file and allowed_file(file.filename):
                ext = file.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
            else:
                flash('Format file tidak didukung!', 'error')
                return redirect(request.url)
        else:
            flash('File gambar wajib diunggah!', 'error')
            return redirect(request.url)

        user_id = session.get('user_id')
        if not user_id:
            flash('Anda harus login untuk menambahkan produk!', 'error')
            return redirect(url_for('login'))

        # Add new product to database
        produk_baru = Product(
            nama_barang=nama_barang,
            harga=int(harga),
            kategori=kategori,
            stok=int(stok),
            deskripsi=deskripsi,
            gambar=filename,
            user_id=user_id
        )
        try:
            db.session.add(produk_baru)
            db.session.commit()
            flash('Produk berhasil ditambahkan!', 'success')
            return redirect(url_for('listProduk'))
        except Exception as e:
            flash(f'Terjadi kesalahan: {e}', 'error')

    return render_template('admin/content/addproduk.html')

# Edit existing product
def editProduk(id):
    product = Product.query.get_or_404(id)

    if request.method == 'POST':
        product.nama_barang = request.form['nama_barang']
        product.harga = request.form['harga']
        product.kategori = request.form['kategori']
        product.stok = request.form['stok']
        product.deskripsi = request.form['deskripsi']

        # Handle file upload for product image (if necessary)
        if 'gambar' in request.files:
            gambar = request.files['gambar']
            if gambar and allowed_file(gambar.filename):
                ext = gambar.filename.rsplit('.', 1)[1].lower()
                filename = f"{uuid.uuid4().hex}.{ext}"
                gambar_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
                gambar.save(gambar_path)
                product.gambar = filename  # Update product image

        # Commit changes to database
        db.session.commit()
        flash('Produk berhasil diperbarui!', 'success')
        return redirect(url_for('listProduk'))  # Redirect to the product list

    return render_template('admin/content/editproduk.html', product=product)

# Delete product
def deleteProduk(id):
    product = Product.query.get_or_404(id)

    # Delete the product from the database
    db.session.delete(product)
    db.session.commit()
    flash('Produk berhasil dihapus!', 'success')

    return redirect(url_for('listProduk'))  # Redirect to the product list

# List all products for the logged-in user
def listProduk():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    dataProduk = Product.query.filter_by(user_id=user.id).all()

    return render_template('admin/content/listproduk.html', dataProduk=dataProduk)