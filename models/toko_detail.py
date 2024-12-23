from models import db
from datetime import datetime

class TokoDetail(db.Model):
    __tablename__ = 'toko_detail'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Updated ForeignKey to match 'users.id'
    no_hp = db.Column(db.String(20), nullable=False)
    bank = db.Column(db.String(50), nullable=False)
    no_rek = db.Column(db.String(50), nullable=False)
    status = db.Column(db.Enum('Pending', 'Approved', 'Rejected', name='status_enum'), default='Pending', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationship to User
    user = db.relationship('User', back_populates='toko_detail')
