from models import db

class SentimentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    sentiment = db.Column(db.String(10), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "text": self.text,
            "sentiment": self.sentiment,
            "created_at": self.created_at.isoformat()
            }