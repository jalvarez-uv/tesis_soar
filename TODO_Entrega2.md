# Hoja de Ruta de Desarrollo Técnico — Entrega 2
**Proyecto:** Diseño e Implementación de una Prueba de Concepto para la Priorización de Vulnerabilidades en Centros de Operaciones de Seguridad (SOC)  
**Autor:** Jorge Eduardo Álvarez Alarcón  
**Profesor Guía:** Cristian Carrión  
**Institución:** Universidad de Valparaíso — Escuela de Ingeniería Civil Informática  

---

## 📋 Resumen Ejecutivo
Este documento define la hoja de ruta técnica y metodológica para el desarrollo de la **Entrega 2 (Seminario de Título II)**. El objetivo principal es transicionar desde la prueba de concepto inicial basada en simulación hacia un entorno funcional conectado a infraestructura real en la Máquina Virtual asignada (Senado), resolviendo las observaciones formuladas por el profesor guía y la comisión evaluadora.

---

## 1. 🌐 Fase de Infraestructura (Senado)
Despliegue, securización y aprovisionamiento del entorno base en la Máquina Virtual provista institucionalmente:

- [ ] **1.1. Preparación del Sistema Operativo Base:**
  - [ ] Verificar la instalación limpia de **Ubuntu 22.04 LTS** (o Debian 12) según los requerimientos solicitados (8 a 16 vCPUs, 16 a 32 GB RAM, 250 a 500 GB SSD).
  - [ ] Validar privilegios de superusuario (`sudo`) para el usuario asignado.
- [ ] **1.2. Conectividad y Acceso Remoto Seguro:**
  - [ ] Configurar y verificar la conexión a través de la **VPN Client-to-Site** institucional.
  - [ ] Habilitar y comprobar el acceso seguro vía **SSH (puerto TCP 22)** con autenticación basada en llaves criptográficas.
- [ ] **1.3. Aprovisionamiento del Motor de Contenedores:**
  - [ ] Instalar la versión más reciente de **Docker Engine** y el plugin **Docker Compose v2+**.
  - [ ] Agregar el usuario local al grupo `docker` para ejecución sin elevación de privilegios.
- [ ] **1.4. Configuración de Puertos y Servicios de Red:**
  - [ ] Habilitar en el cortafuegos interno de la VM los puertos requeridos para gestión y consumo de APIs:
    - `TCP 22`: Acceso SSH de administración.
    - `TCP 443`: Consola web segura.
    - `TCP 55000`: API REST de Wazuh Manager.
    - `TCP 9392`: API / Interfaz de OpenVAS (Greenbone Vulnerability Management - GVM).
  - [ ] Aislar estrictamente el puerto `TCP 27017` (MongoDB) dentro de la red interna de Docker por directrices de seguridad.
- [ ] **1.5. Configuración de Captura de Telemetría y Escaneo:**
  - [ ] Habilitar el canal de telemetría pasiva mediante **Port Mirroring (SPAN Port)** hacia Wazuh en modo escucha no intrusivo.
  - [ ] Configurar el segmento o VLAN asignada para escaneos de vulnerabilidades controlados (o enlazar credenciales API de solo lectura de escáner preexistente).

---

## 2. ⚙️ Fase Backend (Python)
Evolución del motor de orquestación lógica hacia integraciones síncronas en vivo y refinamiento del algoritmo matemático:

- [ ] **2.1. Eliminación Definitiva del Mocking Local:**
  - [ ] Retirar la lectura y dependencia de archivos JSON locales estáticos (`alertas_50_eventos.json`, `openvas_real.json`, `inventario.json`, etc.).
  - [ ] Centralizar la configuración de endpoints, credenciales y tokens mediante variables de entorno (`.env` seguro fuera de control de versiones).
- [ ] **2.2. Implementación de Clientes API REST con `requests`:**
  - [ ] **Conector Wazuh SIEM (puerto 55000):**
    - [ ] Implementar flujo de autenticación JWT (`POST /security/user/authenticate`) con manejo automático de refresco de tokens.
    - [ ] Desarrollar consumo síncrono del endpoint de alertas y eventos de agentes (`GET /alerts` o consulta de índices de eventos).
    - [ ] Implementar agregador/deduplicador dinámico para aislar en tiempo real el peor nivel de regla (`rule.level`) por IP de host atacado.
  - [ ] **Conector OpenVAS / Greenbone:**
    - [ ] Implementar cliente HTTP/REST o wrapper GMP (`python-gvm`) para consultar los reportes de escaneo activos.
    - [ ] Extraer dinámicamente el listado de CVEs detectados y sus correspondientes severidades CVSS Base actualizadas.
- [ ] **2.3. Rediseño del Algoritmo de Priorización Matemática (`motor_soar.py`):**
  - [ ] **Eliminación de la división por 1.2:** Suprimir el divisor analítico de normalización conforme a lo dictaminado por la comisión evaluadora.
  - [ ] **Eliminación de colisiones y empates:** Redefinir la ponderación matemática para evitar escenarios donde múltiples vulnerabilidades críticas empaten en el mismo valor máximo (resolviendo la limitación del LB2).
  - [ ] **Dominancia del Ataque Activo:** Asegurar mediante la estructura de la ecuación o un factor de escala prioritario que la evidencia operativa local de un ataque en curso ($E_o$) siempre prevalezca, garantizando que un activo bajo intrusión activa lidere la cola de triaje por encima de cualquier vulnerabilidad teórica de alto CVSS sin actividad.

---

## 3. 🖥️ Fase Frontend (React)
Corrección de consistencia de datos en la interfaz y mejoras en la experiencia de triaje del analista:

- [ ] **3.1. Corrección del Bug Visual de Inteligencia de Amenazas ($I_t$):**
  - [ ] Resolver la inconsistencia detectada por el profesor guía en las presentaciones previas: asegurar sincronía estricta entre la etiqueta textual y el valor numérico.
  - [ ] Si la fila o badge indica **`CISA KEV Validado`**, garantizar que el parámetro matemático $I_t$ tome efectivamente el valor máximo estipulado ($1.2$ o el valor redefinido en el nuevo modelo), evitando discrepancias en el desglose de cálculo visible para el operador.
- [ ] **3.2. Adaptación a la Nueva Ecuación:**
  - [ ] Actualizar las funciones de visualización de puntuación en `App.jsx` para reflejar la fórmula actualizada sin el factor 1.2.
  - [ ] Ajustar la escala y semántica de colores de los *badges* de riesgo (`badge-critical`, `badge-high`, `badge-medium`, `badge-low`) según los nuevos rangos dinámicos.
- [ ] **3.3. Experiencia de Usuario y Feedback en Vivo:**
  - [ ] Incorporar indicadores de estado de conexión en tiempo real con la VM (estado de API Wazuh, OpenVAS y MongoDB).
  - [ ] Implementar manejo robusto de excepciones y estados de carga (*spinners*) para que la interfaz responda con fluidez durante la ingesta síncrona de datos de red.

---

## 4. 📊 Fase Metodológica y Documental (Informe y Presentación)
Validación formal de la investigación aplicada utilizando datos de producción y consistencia discursiva:

- [ ] **4.1. Diseño del Escenario de Pruebas con Datos Reales:**
  - [ ] Capturar y curar un dataset de telemetría y escaneos reales extraídos de la Máquina Virtual del Senado.
  - [ ] Configurar un escenario heterogéneo que discrimine adecuadamente:
    - Vulnerabilidades con CVSS alto en entornos no críticos o sin ataque activo.
    - Vulnerabilidades con CVSS medio/bajo en activos críticos que estén sufriendo ataques activos comprobados.
- [ ] **4.2. Evaluación Experimental y Métricas:**
  - [ ] Clasificar el dataset de prueba mediante el árbol de decisiones independiente de **SSVC** (*Ground Truth*).
  - [ ] Contrastar empíricamente los resultados frente a las dos líneas base:
    - **Línea Base 1 (LB1):** CVSS puro estático.
    - **Línea Base 2 (LB2):** CVSS $\times C_a$.
    - **Modelo Propuesto (RBVM):** Integración contextual con telemetría de la VM y CISA KEV.
  - [ ] Calcular y documentar formalmente las métricas:
    - $Precision@5$ y $Precision@10$.
    - Tasa de supresión de ruido operacional y falsos positivos.
    - Ausencia de empates artificiales en la cola crítica.
- [ ] **4.3. Consistencia Terminológica y Documental:**
  - [ ] Descartar afirmaciones sobre "reducción de MTTR" en favor de la denominación rigurosa: **"Reducción estimada del esfuerzo de correlación manual"**, detallando los tiempos promedio de cada etapa de triaje.
  - [ ] Mantener total coherencia entre el informe escrito, las diapositivas de defensa y la demostración en vivo del prototipo.
