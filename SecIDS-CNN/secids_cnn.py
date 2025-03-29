import tensorflow as tf
import pandas as pd

class SecIDSModel:
    def __init__(self, model_path="SecIDS-CNN.h5"):
        self.model = tf.keras.models.load_model(model_path)

    def predict(self, data):
        processed_data = self.preprocess_data(data)
        predictions = self.model.predict(processed_data)
        return ["Attack" if pred > 0.5 else "Benign" for pred in predictions]

    def preprocess_data(self, data):
        return data.values