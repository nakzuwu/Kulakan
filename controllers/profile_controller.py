from flask import render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
from app import db
from app.models.user import User
import os
import uuid
from form import ProfileForm


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
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

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
