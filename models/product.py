from models import db

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nama_barang = db.Column(db.String(100), nullable=False)
    harga = db.Column(db.Integer, nullable=False)
    kategori = db.Column(db.String(50), nullable=False)
    stok = db.Column(db.Integer, nullable=False)
    deskripsi = db.Column(db.Text, nullable=True)
    gambar = db.Column(db.String(200), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Link to User table

    # Relationship to fetch the admin associated with the product
    admin = db.relationship('User', backref=db.backref('product', lazy=True))