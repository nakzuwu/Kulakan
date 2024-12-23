import re
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from nltk.corpus import stopwords
import nltk
nltk.download('stopwords')

class SentimentAnalyzer:
    def __init__(self, model_path):
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = AutoModelForSequenceClassification.from_pretrained(model_path)
        self.words_dict = {
            'tdk': 'tidak', 'yg': 'yang', 'ga': 'tidak', 'gak': 'tidak', 'tp': 'tapi', 'd': 'di',
            'sy': 'saya', '&': 'dan', 'dgn': 'dengan', 'utk': 'untuk', 'gk': 'tidak', 'jd': 'jadi',
            'jg': 'juga', 'dr': 'dari', 'krn': 'karena', 'aja': 'saja', 'karna': 'karena', 'udah': 'sudah',
            'kmr': 'kamar', 'g': 'tidak', 'dpt': 'dapat', 'banget': 'sekali', 'bgt': 'sekali', 'kalo': 'kalau',
            'n': 'dan', 'bs': 'bisa', 'oke': 'ok', 'dg': 'dengan', 'pake': 'pakai', 'sampe': 'sampai',
            'dapet': 'dapat', 'ad': 'ada', 'lg': 'lagi', 'bikin': 'buat', 'tak': 'tidak', 'ny': 'nya',
            'ngga': 'tidak', 'nunggu': 'tunggu', 'klo': 'kalau', 'blm': 'belum', 'trus': 'terus', 'kayak': 'seperti',
            'dlm': 'dalam', 'udh': 'sudah', 'tau': 'tahu', 'org': 'orang', 'hrs': 'harus', 'msh': 'masih',
            'sm': 'sama', 'byk': 'banyak', 'krg': 'kurang', 'kmar': 'kamar', 'spt': 'seperti', 'pdhl': 'padahal',
            'chek': 'cek', 'pesen': 'pesan', 'kran': 'keran', 'gitu': 'begitu', 'tpi': 'tapi', 'lbh': 'lebih',
            'tmpt': 'tempat', 'dikasi': 'dikasih', 'serem': 'seram', 'sya': 'saya', 'jgn': 'jangan',
            'dri': 'dari', 'dtg': 'datang', 'gada': 'tidak ada', 'standart': 'standar', 'mlm': 'malam',
            'k': 'ke', 'kl': 'kalau', 'sgt': 'sangat', 'y': 'ya', 'krna': 'karena', 'tgl': 'tanggal',
            'terimakasih': 'terima kasih', 'kecoak': 'kecoa', 'pd': 'pada', 'tdr': 'tidur', 'jdi': 'jadi',
            'kyk': 'seperti', 'sdh': 'sudah', 'ama': 'sama', 'gmana': 'bagaimana', 'dalem': 'dalam',
            'tanyak': 'tanya', 'taru': 'taruh', 'gede': 'besar', 'kaya': 'seperti', 'access': 'akses',
            'tetep': 'tetap', 'mgkin': 'mungkin', 'sower': 'shower', 'idup': 'hidup', 'nyaaa': 'nya',
            'baikk': 'baik', 'hanay': 'hanya', 'tlp': 'telpon', 'kluarga': 'keluarga', 'jln': 'jalan',
            'hr': 'hari', 'ngak': 'tidak', 'bli': 'beli', 'kmar': 'kamar', 'naro': 'taruh'
        }
        self.stop_words = set(stopwords.words('indonesian'))

    def clean_text(self, text):
        text = text.lower()
        for word, replacement in self.words_dict.items():
            text = re.sub(r'\b' + re.escape(word) + r'\b', replacement, text)
        text = ' '.join([word for word in text.split() if word not in self.stop_words])
        return text

    def predict_sentiment(self, text):
        # Clean and preprocess the text
        clean_text_input = self.clean_text(text)
        # Tokenize the text
        inputs = self.tokenizer(clean_text_input, return_tensors="pt", truncation=True, padding=True, max_length=128)
        # Get the model prediction
        outputs = self.model(**inputs)
        logits = outputs.logits
        # Convert logits to probabilities
        probabilities = torch.softmax(logits, dim=1).detach().cpu().numpy()[0]
        # Get the predicted class
        predicted_class = torch.argmax(logits, dim=1).item()
        return predicted_class, probabilities
