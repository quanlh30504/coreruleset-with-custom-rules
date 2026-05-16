import os
import sys

# Suppress TF logging
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

try:
    from tensorflow.keras.models import load_model
except ImportError:
    print("TensorFlow not installed. Please install it to load the Keras model. Run: pip install tensorflow")
    sys.exit(1)

model_path = "AI-train/CNN-BiLSTM/waf_cnn_bilstm_attn.keras"
if not os.path.exists(model_path):
    print(f"Model not found at {model_path}")
    sys.exit(1)

try:
    model = load_model(model_path, compile=False)
    model.summary()

    print("\nLayer details:")
    for layer in model.layers:
        print(f"- {layer.name} ({layer.__class__.__name__})")
except Exception as e:
    print(f"Error loading model: {e}")
