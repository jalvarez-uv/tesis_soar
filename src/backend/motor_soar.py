import json
import requests
import re
import os
from pymongo import MongoClient

def conectar_mongodb():
    return MongoClient("mongodb://localhost:27017/")

def cargar_json_local(ruta):
    if not os.path.exists(ruta):
        raise FileNotFoundError(f"¡FALTA EL ARCHIVO '{ruta}'! Asegúrate de crearlo en la misma carpeta.")
    with open(ruta, 'r') as archivo:
        return json.load(archivo)

def obtener_catalogo_cisa_kev():
    url_cisa = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        respuesta = requests.get(url_cisa, timeout=10)
        respuesta.raise_for_status()
        return {vuln['cveID'] for vuln in respuesta.json().get('vulnerabilities', [])}
    except requests.exceptions.RequestException as e:
        print(f"[!] Aviso: No se pudo conectar a CISA. Usando catálogo local vacío. ({e})")
        return set()

def evaluar_eo(nivel_wazuh):
    if nivel_wazuh >= 10: return 1.2
    elif nivel_wazuh >= 5: return 0.8
    else: return 0.5

def consultar_inteligencia_cti(cve_id, catalogo_cisa_real, catalogo_misp_poc):
    if cve_id in catalogo_cisa_real:
        return 1.2, "CISA KEV Validado (Active)"
    elif cve_id in catalogo_misp_poc:
        return 0.8, "Prueba de Concepto en MISP (PoC)"
    else:
        return 0.5, "Teórica (No catalogada)"

def procesar_lote_eventos():
    coleccion = conectar_mongodb()["soar_db"]["alertas"]
    coleccion.delete_many({}) 
    
    reporte_openvas = cargar_json_local('openvas_real.json')
    datos_inventario = cargar_json_local('inventario.json')
    
    print("[*] Descargando catálogo CISA KEV oficial...")
    catalogo_cisa_real = obtener_catalogo_cisa_kev()
    catalogo_misp_poc = set(cargar_json_local('misp_poc_feed.json'))
    
    # BLINDAJE: Normalización inteligente del Inventario (Soporta listas o diccionarios)
    inventario = {}
    if isinstance(datos_inventario, list):
        for item in datos_inventario:
            inventario[item.get("ip", "")] = {
                "ca": item.get("ca", 1.0), 
                "hostname": item.get("hostname", "Desconocido")
            }
    elif isinstance(datos_inventario, dict):
        for ip, datos in datos_inventario.items():
            inventario[ip] = {
                "ca": datos.get("criticidad_ca", datos.get("ca", 1.0)),
                "hostname": datos.get("hostname", "Desconocido")
            }
    
    # Deduplicación de Wazuh
    peor_ataque_por_ip = {}
    ruta_alertas = 'alertas_50_eventos.json'
    
    if not os.path.exists(ruta_alertas):
        raise FileNotFoundError(f"¡FALTA EL ARCHIVO '{ruta_alertas}'!")
        
    with open(ruta_alertas, 'r') as archivo_alertas:
        for linea in archivo_alertas:
            if not linea.strip(): continue
            alerta = json.loads(linea)
            
            url_log = alerta.get("data", {}).get("url", "")
            match_ip = re.search(r'target=(192\.168\.1\.\d+)', url_log)
            if not match_ip: continue
            ip_afectada = match_ip.group(1)
            
            nivel_actual = int(alerta.get("rule", {}).get("level", 3))
            if ip_afectada not in peor_ataque_por_ip or nivel_actual > peor_ataque_por_ip.get(ip_afectada, 0):
                peor_ataque_por_ip[ip_afectada] = nivel_actual

    procesados = 0
    for hallazgo in reporte_openvas:
        if "nvt" in hallazgo:
            ip_vuln = hallazgo["host"]
            cve = hallazgo["nvt"]["cve"]
            cvss = float(hallazgo["nvt"]["cvss_base"])
        else:
            ip_vuln = hallazgo["ip"]
            cve = hallazgo["cve"]
            cvss = float(hallazgo["cvss"])
        
        nivel_wazuh = peor_ataque_por_ip.get(ip_vuln, 0)
        factor_eo = evaluar_eo(nivel_wazuh)
        ataque_detectado = True if factor_eo >= 0.8 else False
        
        info_activo = inventario.get(ip_vuln, {"ca": 1.0, "hostname": "Desconocido"})
        factor_ca = info_activo["ca"]
        hostname = info_activo["hostname"]
        
        factor_it, etiqueta_cti = consultar_inteligencia_cti(cve, catalogo_cisa_real, catalogo_misp_poc)
        
        m_din = (factor_eo * 0.45) + (factor_ca * 0.35) + (factor_it * 0.20)
        riesgo_final = (cvss * m_din) / 1.2
        
        vuln_enriquecida = {
            "_id": f"{ip_vuln}-{cve}",
            "activo": {"ip": ip_vuln, "hostname": hostname, "criticidad_ca": factor_ca},
            "integracion_openvas": {"cve_id": cve, "score_base_cvss": cvss},
            "telemetria_wazuh": {"ataque_detectado": ataque_detectado, "nivel_regla": nivel_wazuh, "factor_eo": factor_eo},
            "cti": {"factor_it": factor_it, "etiqueta": etiqueta_cti},
            "calculo_rbvm": {
                "multiplicador_dinamico": round(m_din, 3), 
                "riesgo_final_rf": round(riesgo_final, 2), 
                "estado": "Detectada"
            }
        }
        coleccion.insert_one(vuln_enriquecida)
        procesados += 1

    return procesados