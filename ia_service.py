from flask import Flask, request, jsonify
import joblib
import pandas as pd
import os

app = Flask(__name__)

# Cargar el modelo predictor entrenado
try:
    model = joblib.load('modeloPHQ_top11.pkl')
    print("🚀 Microservicio de IA: Modelo .pkl cargado con éxito.")
except Exception as e:
    print(f"⚠️ Alerta: No se pudo cargar el modelo .pkl. Error: {e}")
    model = None

# ENDPOINT ÚNICO: Recibe las respuestas en JSON desde Node.js y devuelve la predicción
@app.route('/api/predict', methods=['POST'])
def predict():
    if not model:
        return jsonify({"error": "El modelo predictivo no está disponible en el servidor de IA."}), 500
    
    # Recibir los datos enviados por Node.js
    data = request.get_json()
    if not data or 'respuestas' not in data:
        return jsonify({"error": "Datos inválidos. Se requiere la lista de respuestas."}), 400
    
    vals = data['respuestas'] # Debe ser una lista de 11 números enteros

    if len(vals) != 11:
        return jsonify({"error": f"Se esperaban 11 respuestas, se recibieron {len(vals)}"}), 400

    # 🌟 SOLUCIÓN INTEGRAL: Asignar las columnas directamente desde los metadatos del modelo
    # Esto elimina cualquier riesgo de discrepancia por espacios dobles o caracteres ocultos
    df = pd.DataFrame([vals], columns=model.feature_names_)
    
    # Realizar la predicción con el modelo .pkl
    pred = model.predict(df)
    
    # Regresar el resultado a Node.js en formato de texto para compatibilidad con EJS
    

    # En ia_service.py
    return jsonify({
        "status": "success",
        "prediccion": str(pred[0][0])  # 🌟 Esto envía "4" en vez de "[4]"
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port)