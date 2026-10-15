import React, { useState, useEffect } from 'react';
import { ShieldAlert, AlertTriangle, Activity, Server, Crosshair, Play, CheckCircle, Trash2, Clock, Sliders } from 'lucide-react';
import './App.css';

function App() {
  const [vulnerabilidades, setVulnerabilidades] = useState([]);
  const [filtro, setFiltro] = useState('Todas');
  const [cargando, setCargando] = useState(false);
  // Estado para alternar entre los 3 modelos (CVSS, LB2, RBVM)
  const [modoVisualizacion, setModoVisualizacion] = useState('RBVM'); 

  const cargarDatos = () => {
    fetch('http://localhost:5000/api/vulnerabilidades')
      .then(res => res.json())
      .then(datos => setVulnerabilidades(datos))
      .catch(error => console.error("Error:", error));
  };

  useEffect(() => {
    cargarDatos();
  }, []);

  const ejecutarMotor = () => {
    setCargando(true);
    fetch('http://localhost:5000/api/ejecutar-motor', { method: 'POST' })
      .then(() => {
        cargarDatos();
        setFiltro('Todas');
        setCargando(false);
      });
  };

  const avanzarEstado = (id, estadoActual) => {
    let nuevoEstado = estadoActual === 'Detectada' ? 'En Triaje' : 'Finalizada';
    fetch(`http://localhost:5000/api/vulnerabilidades/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ estado: nuevoEstado })
    }).then(() => cargarDatos());
  };

  const eliminarVulnerabilidad = (id) => {
    fetch(`http://localhost:5000/api/vulnerabilidades/${id}`, { method: 'DELETE' })
      .then(() => cargarDatos());
  };

  const getBadgeColor = (riesgo) => {
    if (riesgo >= 9.0) return 'badge-critical';
    if (riesgo >= 7.0) return 'badge-high';
    if (riesgo >= 4.0) return 'badge-medium';
    return 'badge-low';
  };

  const vulnerabilidadesFiltradas = vulnerabilidades.filter(v => 
    filtro === 'Todas' || v.calculo_rbvm.estado === filtro
  );

  // Ciclo del botón de 3 estados
  const avanzarModo = () => {
    if (modoVisualizacion === 'RBVM') setModoVisualizacion('CVSS');
    else if (modoVisualizacion === 'CVSS') setModoVisualizacion('LB2');
    else setModoVisualizacion('RBVM');
  };

  // Lógica dinámica de ordenamiento basada en los 3 modelos
  const datosOrdenados = [...vulnerabilidadesFiltradas].sort((a, b) => {
    if (modoVisualizacion === 'CVSS') {
      return b.integracion_openvas.score_base_cvss - a.integracion_openvas.score_base_cvss;
    } else if (modoVisualizacion === 'LB2') {
      const scoreA = Math.min(10.0, a.integracion_openvas.score_base_cvss * a.activo.criticidad_ca);
      const scoreB = Math.min(10.0, b.integracion_openvas.score_base_cvss * b.activo.criticidad_ca);
      return scoreB - scoreA;
    }
    return b.calculo_rbvm.riesgo_final_rf - a.calculo_rbvm.riesgo_final_rf;
  });

  return (
    <div className="soc-dashboard">
      <header className="soc-header">
        <div className="header-title">
          <ShieldAlert size={32} color="#ff4757" />
          <h1>SOAR RBVM | Gestión de Vulnerabilidades</h1>
        </div>
        
        <nav className="soc-nav">
          <button className={filtro === 'Todas' ? 'nav-active' : ''} onClick={() => setFiltro('Todas')}>Global</button>
          <button className={filtro === 'Detectada' ? 'nav-active' : ''} onClick={() => setFiltro('Detectada')}>Nuevas</button>
          <button className={filtro === 'En Triaje' ? 'nav-active' : ''} onClick={() => setFiltro('En Triaje')}>En Triaje</button>
          <button className={filtro === 'Finalizada' ? 'nav-active' : ''} onClick={() => setFiltro('Finalizada')}>Finalizadas</button>
        </nav>

        <div className="header-actions" style={{ display: 'flex', gap: '15px' }}>
          {/* BOTÓN DE MODO DE VISUALIZACIÓN DINÁMICO */}
          <button 
            className="btn-ejecutar" 
            style={{ background: modoVisualizacion === 'RBVM' ? '#3498db' : (modoVisualizacion === 'LB2' ? '#9b59b6' : '#7f8c8d') }}
            onClick={avanzarModo}
          >
            <Sliders size={16} />
            {modoVisualizacion === 'CVSS' ? 'Vista: LB1 (Solo CVSS)' : (modoVisualizacion === 'LB2' ? 'Vista: LB2 (CVSS x Ca)' : 'Vista: Modelo RBVM')}
          </button>

          <button className="btn-ejecutar" onClick={ejecutarMotor} disabled={cargando}>
            {cargando ? <Clock size={16} /> : <Play size={16} />}
            {cargando ? 'Procesando...' : 'Ejecutar Triaje'}
          </button>
        </div>
      </header>

      <main className="soc-content">
        <div className="table-container">
          <table className="soc-table">
            <thead>
              <tr>
                <th>{modoVisualizacion === 'RBVM' ? 'Riesgo Final (Rf)' : (modoVisualizacion === 'LB2' ? 'Puntaje LB2 (CVSS x Ca)' : 'Puntaje CVSS Base')}</th>
                <th>Activo (Criticidad)</th>
                <th>Vulnerabilidad (CISA)</th>
                <th>Telemetría en Vivo (Wazuh)</th>
                <th>Estado</th>
                <th>Acción</th>
              </tr>
            </thead>
            <tbody>
              {datosOrdenados.length === 0 ? (
                <tr>
                  <td colSpan="6" className="center-col" style={{ padding: '40px', color: '#718096' }}>
                    No hay vulnerabilidades en esta vista. Presiona "Ejecutar Triaje" para procesar datos.
                  </td>
                </tr>
              ) : (
                datosOrdenados.map((vuln) => {
                  
                  // Calcular qué puntaje mostrar según la vista seleccionada
                  const puntajeMostrar = modoVisualizacion === 'CVSS' 
                    ? vuln.integracion_openvas.score_base_cvss 
                    : (modoVisualizacion === 'LB2' ? Math.min(10.0, vuln.integracion_openvas.score_base_cvss * vuln.activo.criticidad_ca) : vuln.calculo_rbvm.riesgo_final_rf);
                  
                  // Lógica de iluminación de columnas
                  const isCaDesactivado = modoVisualizacion === 'CVSS';
                  const isCtiWazuhDesactivado = modoVisualizacion !== 'RBVM';

                  return (
                    <tr key={vuln._id} className="alert-row">
                      <td className="center-col">
                        <div className={`risk-badge ${getBadgeColor(puntajeMostrar)}`}>
                          <AlertTriangle size={18} />
                          <span>{puntajeMostrar.toFixed(2)}</span>
                        </div>
                      </td>

                      <td style={{ opacity: isCaDesactivado ? 0.4 : 1 }}>
                        <div className="cell-flex">
                          <Server size={18} className="icon-blue" />
                          <div>
                            <strong>{vuln.activo.ip}</strong>
                            <div className="sub-text">
                              {isCaDesactivado ? "Contexto Ignorado" : `Factor Ca: ${vuln.activo.criticidad_ca}`}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td style={{ opacity: isCtiWazuhDesactivado ? 0.4 : 1 }}>
                        <div className="cell-flex">
                          <Crosshair size={18} className="icon-purple" />
                          <div>
                            <strong>{vuln.integracion_openvas.cve_id}</strong>
                            <div className="sub-text" style={{ 
                              color: isCtiWazuhDesactivado ? '#718096' : (vuln.cti?.factor_it === 1.2 ? '#2ed573' : '#ffa502') 
                            }}>
                              {isCtiWazuhDesactivado ? "Inteligencia CTI Apagada" : (vuln.cti?.etiqueta || "CISA KEV Validado")}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td style={{ opacity: isCtiWazuhDesactivado ? 0.4 : 1 }}>
                        <div className="cell-flex">
                          <Activity size={18} className={!isCtiWazuhDesactivado && vuln.telemetria_wazuh.ataque_detectado ? "icon-red" : "icon-gray"} />
                          <div>
                            <strong>Alerta Nivel {vuln.telemetria_wazuh.nivel_regla || "N/A"}</strong>
                            <div className="sub-text">
                              {isCtiWazuhDesactivado ? "Telemetría Ignorada" : (vuln.telemetria_wazuh.ataque_detectado ? "Ataque Activo" : "Ruido Op.")}
                            </div>
                          </div>
                        </div>
                      </td>

                      <td className="center-col">
                        <span className={`status-badge stat-${vuln.calculo_rbvm.estado.replace(' ', '')}`}>
                          {vuln.calculo_rbvm.estado}
                        </span>
                      </td>

                      <td className="center-col action-cell">
                        {vuln.calculo_rbvm.estado !== 'Finalizada' ? (
                          <button className="btn-avanzar" onClick={() => avanzarEstado(vuln._id, vuln.calculo_rbvm.estado)}>
                            {vuln.calculo_rbvm.estado === 'Detectada' ? 'Revisar' : 'Marcar Resuelto'}
                          </button>
                        ) : (
                          <button className="btn-eliminar" onClick={() => eliminarVulnerabilidad(vuln._id)}>
                            <Trash2 size={16} /> Remediar
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}

export default App;