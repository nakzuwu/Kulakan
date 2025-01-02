import re
from flask import render_template, request, redirect, url_for, session, flash, jsonify, make_response, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from models.user import User
from models import db
from datetime import datetime, timedelta
import jwt 

#web

def validate_email(email):
    # Email regex pattern to match valid email addresses
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email)

def validate_password(password):
    # Password must be at least 8 characters long, contain at least one uppercase letter, and one digit
    password_regex = r'^(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$'
    return re.match(password_regex, password)

def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password)

        # Validate email
        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('auth/register.html')

        # Validate password
        if not validate_password(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, and one digit.', 'danger')
            return render_template('auth/register.html')

        # Check if the email is already registered
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered.', 'danger')
        else:
            new_user = User(name=name, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('auth/register.html')

def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Email validation
        if not validate_email(email):
            flash('Please enter a valid email address.', 'danger')
            return render_template('auth/login.html')

        # Password validation
        if not validate_password(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, and one digit.', 'danger')
            return render_template('auth/login.html')

        # Find user by email
        user = User.query.filter_by(email=email).first()

        # Verify password
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_role'] = user.role  # Store user role in session

            flash('Login successful!', 'success')

            # Redirect based on role
            if user.role == 'super_admin':
                return redirect(url_for('home'))  # Dashboard for super admin
            elif user.role == 'store_admin':
                return redirect(url_for('dashboard'))  # Dashboard for store admin
            else:
                return redirect(url_for('home'))  # Dashboard for regular user

        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('auth/login.html')

def logout():
    session.clear()

    # Remove the cart cookie (if exists)
    response = make_response(redirect(url_for('login')))
    response.delete_cookie('cart')  # Delete the cart cookie

    flash('Anda telah logout.', 'info')  # Flash message for the user

    return response

def reset_password(token):
    try:
        data = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])

        if not user:
            flash('Token tidak valid atau telah kadaluarsa.', 'danger')
            return redirect(url_for('forgot_password'))

        if request.method == 'POST':
            new_password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')

            if not new_password or new_password != confirm_password:
                flash('Password tidak cocok atau kosong.', 'danger')
                return render_template('auth/reset_password.html', token=token)

            if len(new_password) < 6:
                flash('Password harus minimal 6 karakter.', 'danger')
                return render_template('auth/reset_password.html', token=token)

            user.password = generate_password_hash(new_password)
            db.session.commit()
            flash('Password berhasil diubah. Silakan login.', 'success')
            return redirect(url_for('login'))

        return render_template('auth/reset_password.html', token=token)

    except jwt.ExpiredSignatureError:
        flash('Token telah kadaluarsa.', 'danger')
        return redirect(url_for('forgot_password'))
    except jwt.InvalidTokenError:
        flash('Token tidak valid.', 'danger')
        return redirect(url_for('forgot_password'))
    except Exception as e:
        flash(f"Terjadi kesalahan: {str(e)}", 'danger')
        return redirect(url_for('forgot_password'))

#api

def api_register():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'error': 'All fields are required.'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address.'}), 400

    if not validate_password(password):
        return jsonify({'error': 'Password must be at least 8 characters long, contain at least one uppercase letter, and one digit.'}), 400

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'error': 'Email already registered.'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(name=name, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'Registration successful. Please login.'}), 201

def api_login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required.'}), 400

    if not validate_email(email):
        return jsonify({'error': 'Invalid email address.'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid email or password.'}), 401

    session['user_id'] = user.id
    session['user_name'] = user.name
    session['user_role'] = user.role

    response = make_response(jsonify({'message': 'Login successful!', 'role': user.role}), 200)
    response.set_cookie('session', session.sid, httponly=True)  # Securely set the session cookie
    return response


def api_logout():
    session.clear()
    return jsonify({'message': 'You have been logged out.'}), 200