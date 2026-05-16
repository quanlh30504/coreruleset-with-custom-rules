import os
import sys
import pickle
import numpy as np
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Suppress TF logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

sys.path.insert(0, os.path.abspath("AI-train/CNN-BiLSTM"))

from AttentionLayer import AttentionLayer
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.sequence import pad_sequences

app = FastAPI(title="WAF CNN-BiLSTM API", version="1.0")

# Globals
model = None
tokenizer = None
max_len = 200

class PayloadRequest(BaseModel):
    payload: str

class PredictResponse(BaseModel):
    is_malicious: bool
    confidence: float

@app.on_event("startup")
async def startup_event():
    global model, tokenizer, max_len
    print("Loading tokenizer...")
    with open("AI-train/CNN-BiLSTM/waf_tokenizer.pkl", "rb") as f:
        tokenizer = pickle.load(f)
    print("Loading model...")
    model = load_model("AI-train/CNN-BiLSTM/waf_cnn_bilstm_attn.keras", custom_objects={'AttentionLayer': AttentionLayer})
    max_len = model.input_shape[1]
    print(f"Server ready. Max sequence length: {max_len}")

@app.post("/predict", response_model=PredictResponse)
async def predict(request: PayloadRequest):
    if not model or not tokenizer:
        raise HTTPException(status_code=503, detail="Model is not loaded.")
    
    seqs = tokenizer.texts_to_sequences([request.payload])
    padded = pad_sequences(seqs, maxlen=max_len, padding='post', truncating='post')
    
    # Predict
    prob = float(model.predict(padded, verbose=0)[0][0])
    
    return PredictResponse(
        is_malicious=(prob > 0.5),
        confidence=prob
    )

if __name__ == "__main__":
    import uvicorn
    # Make sure to run from project root: python benchmark/waf_vs_ai/api_server.py
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=False)
