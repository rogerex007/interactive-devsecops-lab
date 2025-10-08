
import React from 'react'
import { createRoot } from 'react-dom/client'

function App() {
  const [status, setStatus] = React.useState(null)
  const [labs, setLabs] = React.useState([])
  const [running, setRunning] = React.useState(null)
  const [results, setResults] = React.useState([])
  const [error, setError] = React.useState(null)

  const loadResults = React.useCallback(() => {
    fetch('/api/results')
      .then(resp => {
        if (!resp.ok) throw new Error('No se pudieron cargar los resultados')
        return resp.json()
      })
      .then(data => setResults(data))
      .catch(err => setError(err.message))
  }, [])

  React.useEffect(() => {
    fetch('/api/health')
      .then(r => r.json())
      .then(data => setStatus(data))
      .catch(() => setStatus(null))

    fetch('/api/labs')
      .then(r => r.json())
      .then(data => setLabs(data))
      .catch(() => setLabs([]))

    loadResults()
  }, [loadResults])

  const runJob = async (labId, job) => {
    setError(null)
    setRunning({ labId, job, startedAt: new Date().toISOString() })

    try {
      const resp = await fetch(`/api/labs/${labId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ job })
      })

      if (!resp.ok) {
        throw new Error('No se pudo iniciar el job')
      }

      const data = await resp.json()
      setRunning({ ...data, labId })

      setTimeout(() => {
        loadResults()
        setRunning(null)
      }, 2500)
    } catch (err) {
      setError(err.message)
      setRunning(null)
    }
  }

  const formatUpdatedAt = value => {
    try {
      return new Date(value).toLocaleString()
    } catch (err) {
      return value
    }
  }

  return (
    <div style={{ fontFamily: 'Arial, sans-serif', padding: 20, background: '#f9fafb', minHeight: '100vh' }}>
      <h1 style={{ marginBottom: 8 }}>DevSecOps Lab - Dashboard</h1>
      <p style={{ marginTop: 0, color: '#4b5563' }}>
        Panel inicial para monitorear servicios base y ejecutar simulaciones de escaneo.
      </p>

      {error && (
        <div style={{ background: '#fee2e2', color: '#991b1b', padding: 12, borderRadius: 6, marginBottom: 16 }}>
          {error}
        </div>
      )}

      <section style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ margin: 0 }}>Estado de servicios</h2>
          <button onClick={() => {
            setStatus(null)
            fetch('/api/health')
              .then(r => r.json())
              .then(data => setStatus(data))
              .catch(() => setStatus(null))
          }}>Actualizar</button>
        </div>
        <pre style={{ background: '#111827', color: '#f9fafb', padding: 16, borderRadius: 6, minHeight: 120 }}>
          {status ? JSON.stringify(status, null, 2) : 'Cargando...'}
        </pre>
      </section>

      <section style={{ marginBottom: 24 }}>
        <h2>Laboratorios disponibles</h2>
        {labs.length === 0 ? (
          <p>No hay laboratorios disponibles.</p>
        ) : (
          <ul style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {labs.map(lab => (
              <li key={lab.id} style={{ background: '#fff', padding: 16, borderRadius: 6, marginBottom: 12, boxShadow: '0 1px 2px rgba(15, 23, 42, 0.1)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <strong>{lab.name}</strong>
                    <div style={{ fontSize: 12, color: '#6b7280' }}>{lab.id}</div>
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button onClick={() => runJob(lab.id, 'semgrep')}>Ejecutar Semgrep</button>
                    <button onClick={() => runJob(lab.id, 'trivy')}>Ejecutar Trivy</button>
                    <button onClick={() => runJob(lab.id, 'zap')}>Ejecutar ZAP</button>
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
        <div style={{ marginTop: 12, color: '#4b5563' }}>
          {running ? `Ejecutando ${running.job} para ${running.labId}...` : 'Ningún job en ejecución'}
        </div>
      </section>

      <section>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h2 style={{ margin: 0 }}>Resultados recientes</h2>
          <button onClick={loadResults}>Actualizar</button>
        </div>
        {results.length === 0 ? (
          <p style={{ color: '#6b7280' }}>Aún no hay resultados disponibles. Ejecuta un escaneo para generar reportes.</p>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 12 }}>
              <thead>
                <tr style={{ background: '#e5e7eb', textAlign: 'left' }}>
                  <th style={{ padding: '8px 12px' }}>Laboratorio</th>
                  <th style={{ padding: '8px 12px' }}>Job</th>
                  <th style={{ padding: '8px 12px' }}>Última actualización</th>
                  <th style={{ padding: '8px 12px' }}>Reporte</th>
                  <th style={{ padding: '8px 12px' }}>Logs</th>
                </tr>
              </thead>
              <tbody>
                {results.map(result => (
                  <tr key={result.file} style={{ borderBottom: '1px solid #e5e7eb' }}>
                    <td style={{ padding: '8px 12px' }}>{result.labId}</td>
                    <td style={{ padding: '8px 12px', textTransform: 'capitalize' }}>{result.job}</td>
                    <td style={{ padding: '8px 12px' }}>{formatUpdatedAt(result.updatedAt)}</td>
                    <td style={{ padding: '8px 12px' }}>
                      <a href={result.url} target="_blank" rel="noreferrer">Descargar</a>
                    </td>
                    <td style={{ padding: '8px 12px' }}>
                      {result.logUrl ? (
                        <a href={result.logUrl} target="_blank" rel="noreferrer">Ver logs</a>
                      ) : (
                        <span style={{ color: '#9ca3af' }}>No disponible</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  )
}

createRoot(document.getElementById('root')).render(<App />)
