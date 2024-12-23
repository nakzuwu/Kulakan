from flask import Blueprint, request, jsonify
from llama_index.core import (
    VectorStoreIndex,
    StorageContext,
    ServiceContext,
    load_index_from_storage
)
from llama_index.embeddings.huggingface import HuggingFaceEmbedding
from llama_index.llms.groq import Groq
import os

# Setup Blueprint
GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# Define the embedding and LLM models
embed_model = HuggingFaceEmbedding(model_name="sentence-transformers/all-MiniLM-L12-v2")
llm = Groq(model="llama-3.2-90b-vision-preview", api_key=GROQ_API_KEY)

# Configure Service Context
service_context = ServiceContext.from_defaults(embed_model=embed_model, llm=llm)

# Define Storage Context
storage_context = StorageContext.from_defaults(persist_dir="D:\storage_mini")

# Load Index
index = load_index_from_storage(storage_context, service_context=service_context)

# Query Engine
query_engine = index.as_query_engine(service_context=service_context)
def chat():
    try:
        # Get user input from request
        user_input = request.json.get('message', '').strip()
        if not user_input:
            return jsonify({'response': 'Pesan kosong, silakan masukkan pesan valid.'}), 400
        
        # Query the LLM
        response = query_engine.query(user_input)
        
        # Return the response
        return jsonify({'response': response.response})
    except Exception as e:
        # Handle errors gracefully
        return jsonify({'error': str(e), 'response': 'Terjadi kesalahan. Silakan coba lagi nanti.'}), 500