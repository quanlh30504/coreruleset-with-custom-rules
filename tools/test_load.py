import sys
import pickle
import numpy as np

# Load AttentionLayer
sys.path.insert(0, "AI-train/CNN-BiLSTM")
try:
    from AttentionLayer import AttentionLayer
    from tensorflow.keras.models import load_model
    from tensorflow.keras.preprocessing.sequence import pad_sequences
except Exception as e:
    print(f"Import error: {e}")
    sys.exit(1)

try:
    print("Loading tokenizer...")
    with open("AI-train/CNN-BiLSTM/waf_tokenizer.pkl", "rb") as f:
        tokenizer = pickle.load(f)

    print(f"Vocab size: {len(tokenizer.word_index)}")

    print("Loading model...")
    model = load_model("AI-train/CNN-BiLSTM/waf_cnn_bilstm_attn.keras", custom_objects={'AttentionLayer': AttentionLayer})
    print(f"Model input shape: {model.input_shape}")

    # Test predict
    test_texts = ["<script>alert(1)</script>", "select * from users"]
    seqs = tokenizer.texts_to_sequences(test_texts)
    max_len = model.input_shape[1]
    print(f"Using max_len: {max_len}")
    padded = pad_sequences(seqs, maxlen=max_len, padding='post', truncating='post')

    preds = model.predict(padded)
    print(f"Predictions: {preds}")
except Exception as e:
    print(f"Execution error: {e}")
