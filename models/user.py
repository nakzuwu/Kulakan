from models import db

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    address = db.Column(db.String(255), nullable=True)
    profile_photo = db.Column(db.String(100), nullable=True, default='default.jpg')  # Default photo
    role = db.Column(db.Enum('user', 'store_admin', 'super_admin', name='user_roles'), default='user')  # Default role 'user'

    # Relationship to fetch products
    products = db.relationship('Product', backref='owner', lazy=True)
    toko_detail = db.relationship('TokoDetail', back_populates='user', uselist=False)


    def __init__(self, name, email, password, address=None, profile_photo='default.jpg', role='user'):
        self.name = name
        self.email = email
        self.password = password
        self.address = address
        self.profile_photo = profile_photo
        self.role = role  