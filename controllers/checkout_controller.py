from flask import session, render_template, request, redirect, url_for, flash ,jsonify, make_response
from models.product import Product
from models.user import User
from models import db
import json

def get_user_from_session():
    user_id = session.get('user_id')  # Get the user_id from the session
    if user_id:
        user = User.query.get(user_id)  # Retrieve the user from the database
        return user
    return None

def add_to_cart(product_id):
    user = get_user_from_session()  # Use the get_user_from_session() function
    if not user:
        return redirect(url_for('login'))  # Redirect to login if user is not authenticated

    product = Product.query.get_or_404(product_id)

    # Initialize the cart if it doesn't exist
    if 'cart' not in session:
        session['cart'] = []  # Initialize cart in the session

    cart = session['cart']

    # Check if the product is already in the cart
    for item in cart:
        if item['product_id'] == product_id:
            # Check stock and update quantity
            if item['quantity'] < product.stok:
                item['quantity'] += 1
                flash(f'{product.nama_barang} has been updated in your cart.', 'success')
            else:
                flash(f'Stock limit reached for {product.nama_barang}.', 'danger')
            session.modified = True
            response = make_response(redirect(url_for('keranjang')))
            # Store cart in a cookie
            response.set_cookie('cart', json.dumps(cart), max_age=60*60*24*30)  # Set cookie to last for 30 days
            return response

    cart.append({'product_id': product_id, 'quantity': 1})
    session['cart'] = cart  
    flash(f'{product.nama_barang} added to cart.', 'success')
    response = make_response(redirect(url_for('keranjang')))
    response.set_cookie('cart', json.dumps(cart), max_age=60*60*24*30)  # Set cookie to last for 30 days
    return response

def keranjang():
    user = get_user_from_session()  # Use the get_user_from_session() function
    if not user:
        return redirect(url_for('login'))  # Redirect to login if user is not authenticated

    # Check if 'cart' exists in the session or cookie
    if 'cart' not in session:
        cart_cookie = request.cookies.get('cart')  # Try to load cart from cookie if not in session
        if cart_cookie:
            session['cart'] = json.loads(cart_cookie)
        else:
            session['cart'] = []  # Initialize an empty cart if no cookie

    cart = session['cart']
    products = []

    # Retrieve product details from the database
    for item in cart:
        product = Product.query.get(item['product_id'])
        if product:
            store_name = User.query.get(product.user_id).name if product.user_id else 'Tidak Diketahui'  # Use product.user for store name
            product_details = {
                'id': product.id,
                'name': product.nama_barang,
                'price': product.harga,
                'quantity': item['quantity'],
                'image': product.gambar,
                'store_name': store_name,  # Store name based on the product's user_id
                'stock': product.stok,
                'total_price': product.harga * item['quantity']  # Ensure correct calculation
            }
            products.append(product_details)

    # Calculate the subtotal for selected items
    subtotal = sum(item['total_price'] for item in products)

    return render_template('frontend/keranjang.html', products=products, subtotal=subtotal)



def update_cart():
    user = get_user_from_session()  # Use the get_user_from_session() function
    if not user:
        return redirect(url_for('login'))  # Redirect to login if user is not authenticated

    data = request.get_json()
    product_id = int(data['product_id'])
    new_quantity = int(data['quantity'])

    if 'cart' not in session:
        return jsonify({'error': 'Cart not found'}), 400

    cart = session['cart']
    subtotal = 0

    for item in cart:
        if item['product_id'] == product_id:
            product = Product.query.get(product_id)
            if product and new_quantity <= product.stok:  # Ensure stock limits are respected
                item['quantity'] = new_quantity
                item['total_price'] = new_quantity * product.harga

    session['cart'] = cart  # Save updated cart back to session

    # Return updated total price for the product
    return jsonify({
        'total_price': new_quantity * product.harga
    })


def payment():
    if 'cart' not in session or not session['cart']:
        return redirect(url_for('keranjang'))  # Jika keranjang kosong, arahkan ke halaman keranjang
    
    # Ambil data pengguna
    user_id = session.get('user_id')  # Asumsi user_id disimpan di session setelah login
    user = User.query.get(user_id)
    
    if user is None:
        return redirect(url_for('login'))  # Jika pengguna tidak ditemukan, arahkan ke login
    
    # Ambil data produk yang dipilih di keranjang
    cart = session['cart']
    products = []
    total_price = 0
    for item in cart:
        product = Product.query.get(item['product_id'])
        if product:
            total_price += product.harga * item['quantity']
            products.append({
                'name': product.nama_barang,
                'price': product.harga,
                'quantity': item['quantity'],
                'total_price': product.harga * item['quantity'],
                'image': product.gambar
            })
    
    # Logika untuk menghitung biaya tambahan berdasarkan metode pembayaran
    if request.method == 'POST':
        payment_method = request.form['payment_method']
        if payment_method == 'bank_transfer':
            additional_cost = 5000  # Biaya transfer bank
            total_price += additional_cost
        elif payment_method == 'cod':
            additional_cost = 15000  # Biaya COD
            total_price += additional_cost
        elif payment_method == 'e_wallet':
            additional_cost = 2000  # Biaya e-wallet
            total_price += additional_cost

        # Pajak dan biaya pengiriman
        tax = total_price * 0.1  # Pajak 10%
        shipping = 20000  # Biaya pengiriman tetap
        total_price += tax + shipping

        return redirect(url_for('process_payment', total=total_price))  # Redirect ke halaman pembayaran
    
    return render_template('frontend/payment.html', user=user, products=products, total_price=total_price)


def process_payment(total):
    return render_template('frontend/payment_processing.html', total=total)