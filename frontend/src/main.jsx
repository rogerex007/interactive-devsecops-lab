
import React from 'react'
import { createRoot } from 'react-dom/client'

function App() {
  const [status, setStatus] = React.useState(null);
  const [labs, setLabs] = React.useState([]);
  const [running, setRunning] = React.useState(null);

  React.useEffect(()=>{
    fetch('/api/health').then(r=>r.json()).then(setStatus);
    fetch('/api/labs').then(r=>r.json()).then(setLabs);
  },[]);

  const runJob = async (labId, job) => {
    setRunning(`${job} on ${labId}`);
    const resp = await fetch(`/api/labs/${labId}/run`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ job }) });
    const j = await resp.json();
    console.log(j);
    setTimeout(()=>setRunning(null), 2000);
  }

  return (<div style={{fontFamily:'Arial, sans-serif', padding:20}}>
    <h1>DevSecOps Lab - Dashboard</h1>
    <pre>{status ? JSON.stringify(status,null,2) : 'Cargando...'}</pre>
    <h2>Labs</h2>
    <ul>
      {labs.map(l=> <li key={l.id}>
        <strong>{l.name}</strong> &nbsp;
        <button onClick={()=>runJob(l.id,'semgrep')}>Run Semgrep</button>
        <button onClick={()=>runJob(l.id,'trivy')}>Run Trivy</button>
        <button onClick={()=>runJob(l.id,'zap')}>Run ZAP</button>
      </li>)}
    </ul>
    <div>{running ? `Ejecutando: ${running}` : 'Ningún job en ejecución'}</div>
  </div>)

}

createRoot(document.getElementById('root')).render(<App />)
