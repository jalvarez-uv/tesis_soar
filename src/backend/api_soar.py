from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo import MongoClient
import motor_soar
import traceback # <--- NUEVO: Para ver los errores reales

app = Flask(__name__)
CORS(app)

def conectar_mongodb():
    return MongoClient("mongodb://localhost:27017/")

@app.route('/api/vulnerabilidades', methods=['GET'])
def obtener_vulnerabilidades():
    try:
        cliente = conectar_mongodb()
        coleccion = cliente["soar_db"]["alertas"]
        vulnerabilidades = list(coleccion.find({}).sort("calculo_rbvm.riesgo_final_rf", -1))
        return jsonify(vulnerabilidades)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ejecutar-motor', methods=['POST'])
def ejecutar_motor():
    try:
        total = motor_soar.procesar_lote_eventos()
        return jsonify({"mensaje": f"Motor ejecutado exitosamente. {total} procesadas."})
    except Exception as e:
        # NUEVO: Esto imprimirá el error real en tu terminal para que sepamos qué pasa
        print("========== ERROR EN EL MOTOR ==========")
        traceback.print_exc() 
        print("=======================================")
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerabilidades/<id_vuln>', methods=['PUT'])
def actualizar_estado(id_vuln):
    try:
        nuevo_estado = request.json.get('estado')
        cliente = conectar_mongodb()
        cliente["soar_db"]["alertas"].update_one(
            {"_id": id_vuln},
            {"$set": {"calculo_rbvm.estado": nuevo_estado}}
        )
        return jsonify({"mensaje": "Estado actualizado"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vulnerabilidades/<id_vuln>', methods=['DELETE'])
def eliminar_vuln(id_vuln):
    try:
        cliente = conectar_mongodb()
        cliente["soar_db"]["alertas"].delete_one({"_id": id_vuln})
        return jsonify({"mensaje": "Vulnerabilidad remediada y eliminada"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print("[*] Levantando API REST del SOAR en el puerto 5000...")
    app.run(debug=True, port=5000)