import React, { useState, useEffect } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement,
} from 'chart.js';
import { Bar, Doughnut, Line } from 'react-chartjs-2';
import WorkflowManager from './WorkflowManager';

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  PointElement,
  LineElement
);

const SecurityDashboard = () => {
  const [status, setStatus] = useState(null);
  const [labs, setLabs] = useState([]);
  const [running, setRunning] = useState(null);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);
  const [viewingReport, setViewingReport] = useState(null);
  const [viewingLog, setViewingLog] = useState(null);
  const [reportContent, setReportContent] = useState(null);
  const [logContent, setLogContent] = useState(null);
  const [parsedReportData, setParsedReportData] = useState(null);
  const [selectedTool, setSelectedTool] = useState('all');
  const [runningJobs, setRunningJobs] = useState([]);
  const [dashboardData, setDashboardData] = useState({
    toolCounts: {},
    severityCounts: { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, WARNING: 0, CRITICAL: 0 },
    vulnerabilityTypes: {},
    cveData: [],
    totalVulnerabilities: 0
  });
  const [showWorkflowManager, setShowWorkflowManager] = useState(false);

  // Cargar resultados
  const loadResults = React.useCallback(() => {
    fetch('http://localhost:4000/api/results')
      .then(resp => {
        if (!resp.ok) throw new Error('No se pudieron cargar los resultados');
        return resp.json();
      })
      .then(data => setResults(data))
      .catch(err => setError(err.message));
  }, []);

  useEffect(() => {
    fetch('http://localhost:4000/api/health')
      .then(r => r.json())
      .then(data => setStatus(data))
      .catch(() => setStatus(null));

    fetch('http://localhost:4000/api/labs')
      .then(r => r.json())
      .then(data => setLabs(data))
      .catch(() => setLabs([]));

    loadResults();
  }, [loadResults]);

  // Procesar datos del dashboard cuando cambien los resultados
  useEffect(() => {
    if (results.length === 0) return;

    const processData = async () => {
      const filteredResults = selectedTool === 'all' ? results : results.filter(r => r.job === selectedTool);
      
      const toolCounts = {};
      const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, WARNING: 0, CRITICAL: 0 };
      const vulnerabilityTypes = {};
      const cveData = [];

      // Procesar cada resultado
      for (const result of filteredResults) {
        toolCounts[result.job] = (toolCounts[result.job] || 0) + 1;
        
        try {
          const response = await fetch(`http://localhost:4000${result.url}`);
          const reportData = await response.json();
          
          if (result.job === 'semgrep') {
            const findings = reportData.results || [];
            findings.forEach(finding => {
              let severity = 'MEDIUM';
              if (finding.extra?.metadata?.category === 'security') {
                if (finding.extra?.metadata?.cwe?.includes('CWE-352') || 
                    finding.extra?.metadata?.cwe?.includes('CWE-89') ||
                    finding.extra?.metadata?.cwe?.includes('CWE-79')) {
                  severity = 'HIGH';
                }
              }
              if (finding.extra?.metadata?.cwe2022_top25 || finding.extra?.metadata?.cwe2021_top25) {
                severity = 'HIGH';
              }
              
              severityCounts[severity] = (severityCounts[severity] || 0) + 1;
              
              const vulnType = finding.extra?.metadata?.vulnerability_class?.[0] || finding.check_id?.split('.').pop() || 'Unknown';
              vulnerabilityTypes[vulnType] = (vulnerabilityTypes[vulnType] || 0) + 1;
            });
          } else if (result.job === 'trivy') {
            if (reportData.Results) {
              reportData.Results.forEach(result => {
                if (result.Vulnerabilities) {
                  result.Vulnerabilities.forEach(vuln => {
                    const severity = vuln.Severity || 'UNKNOWN';
                    severityCounts[severity] = (severityCounts[severity] || 0) + 1;
                    
                    cveData.push({
                      id: vuln.VulnerabilityID,
                      severity: severity,
                      package: vuln.PkgName,
                      version: vuln.InstalledVersion,
                      cvss: vuln.CVSS?.nvd?.V3Score || vuln.CVSS?.nvd?.V2Score || 'N/A',
                      published: vuln.PublishedDate,
                      fixedVersion: vuln.FixedVersion,
                      description: vuln.Description
                    });
                  });
                }
              });
            }
          }
        } catch (error) {
          console.error('Error loading report:', error);
        }
      }

      setDashboardData({
        toolCounts,
        severityCounts,
        vulnerabilityTypes,
        cveData,
        totalVulnerabilities: Object.values(severityCounts).reduce((a, b) => a + b, 0)
      });
    };

    processData();
  }, [results, selectedTool]);

  const runJob = async (labId, job) => {
    setError(null);
    setRunning({ labId, job, startedAt: new Date().toISOString() });
    setRunningJobs(prev => [...prev, job]);

    try {
      const resp = await fetch(`http://localhost:4000/api/labs/${labId}/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ job })
      });

      if (!resp.ok) {
        throw new Error('No se pudo iniciar el job');
      }

      const data = await resp.json();
      setRunning({ ...data, labId });

      setTimeout(() => {
        loadResults();
        setRunning(null);
        setRunningJobs(prev => prev.filter(j => j !== job));
      }, 2500);
    } catch (err) {
      setError(err.message);
      setRunning(null);
      setRunningJobs(prev => prev.filter(j => j !== job));
    }
  };

  const viewReport = async (result) => {
    try {
      const response = await fetch(`http://localhost:4000${result.url}`);
      const content = await response.text();
      setReportContent(content);
      setViewingReport(result);
      
      // Parsear el reporte según el tipo de herramienta
      let parsedData = null;
      try {
        const jsonData = JSON.parse(content);
        console.log('JSON Data:', jsonData);
        
        if (result.job === 'semgrep') {
          parsedData = parseSemgrepReport(jsonData);
        } else if (result.job === 'trivy') {
          parsedData = parseTrivyReport(jsonData);
        } else if (result.job === 'zap') {
          parsedData = parseZapReport(jsonData);
        }
        
        console.log('Parsed Data:', parsedData);
      } catch (e) {
        console.error('Parse error:', e);
        parsedData = { error: 'No se pudo parsear el reporte', raw: content };
      }
      
      setParsedReportData(parsedData);
    } catch (err) {
      setError('No se pudo cargar el reporte: ' + err.message);
    }
  };

  // Función para parsear reportes de Semgrep
  const parseSemgrepReport = (data) => {
    const findings = data.results || [];
    const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, ERROR: 0 };
    const ruleCounts = {};
    const fileCounts = {};
    
    findings.forEach(finding => {
      // Determinar severidad basada en la categoría y CWE
      let severity = 'MEDIUM'; // Por defecto
      
      if (finding.extra?.metadata?.category === 'security') {
        if (finding.extra?.metadata?.cwe?.includes('CWE-352') || 
            finding.extra?.metadata?.cwe?.includes('CWE-89') ||
            finding.extra?.metadata?.cwe?.includes('CWE-79')) {
          severity = 'HIGH';
        }
      }
      
      if (finding.extra?.metadata?.cwe2022_top25 || finding.extra?.metadata?.cwe2021_top25) {
        severity = 'HIGH';
      }
      
      severityCounts[severity]++;
      
      const rule = finding.check_id?.split('.').pop() || 'Unknown';
      ruleCounts[rule] = (ruleCounts[rule] || 0) + 1;
      
      const file = finding.path || 'Unknown';
      fileCounts[file] = (fileCounts[file] || 0) + 1;
    });

    return {
      tool: 'Semgrep',
      type: 'SAST',
      totalFindings: findings.length,
      severityCounts,
      ruleCounts,
      fileCounts,
      findings: findings.map(f => ({
        id: f.check_id,
        rule: f.check_id?.split('.').pop() || 'Unknown',
        severity: (() => {
          let severity = 'MEDIUM';
          if (f.extra?.metadata?.category === 'security') {
            if (f.extra?.metadata?.cwe?.includes('CWE-352') || 
                f.extra?.metadata?.cwe?.includes('CWE-89') ||
                f.extra?.metadata?.cwe?.includes('CWE-79')) {
              severity = 'HIGH';
            }
          }
          if (f.extra?.metadata?.cwe2022_top25 || f.extra?.metadata?.cwe2021_top25) {
            severity = 'HIGH';
          }
          return severity;
        })(),
        message: f.extra?.message || 'No message',
        file: f.path,
        line: f.start?.line || 0,
        column: f.start?.col || 0,
        snippet: f.extra?.lines || '',
        description: f.extra?.metadata?.description || '',
        impact: f.extra?.metadata?.impact || '',
        confidence: f.extra?.metadata?.confidence || 'MEDIUM',
        cwe: f.extra?.metadata?.cwe?.[0] || '',
        owasp: f.extra?.metadata?.owasp?.[0] || '',
        references: f.extra?.metadata?.references || []
      }))
    };
  };

  // Función para parsear reportes de Trivy
  const parseTrivyReport = (data) => {
    const vulnerabilities = [];
    const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0, CRITICAL: 0, UNKNOWN: 0 };
    const packageCounts = {};
    const cweCounts = {};
    
    (data.Results || []).forEach(result => {
      if (result.Vulnerabilities) {
        result.Vulnerabilities.forEach(vuln => {
          const severity = vuln.Severity || 'UNKNOWN';
          severityCounts[severity]++;
          
          const pkg = vuln.PkgName || 'Unknown';
          packageCounts[pkg] = (packageCounts[pkg] || 0) + 1;
          
          if (vuln.CweIDs) {
            vuln.CweIDs.forEach(cwe => {
              cweCounts[cwe] = (cweCounts[cwe] || 0) + 1;
            });
          }
          
          vulnerabilities.push({
            id: vuln.VulnerabilityID,
            title: vuln.Title,
            description: vuln.Description,
            severity: severity,
            cvss: vuln.CVSS?.ghsa?.V3Score || vuln.CVSS?.nvd?.V3Score || 0,
            package: pkg,
            version: vuln.InstalledVersion,
            fixedVersion: vuln.FixedVersion,
            cwe: vuln.CweIDs?.[0],
            references: vuln.References,
            publishedDate: vuln.PublishedDate,
            lastModifiedDate: vuln.LastModifiedDate
          });
        });
      }
    });

    return {
      tool: 'Trivy',
      type: 'SCA',
      totalFindings: vulnerabilities.length,
      severityCounts,
      packageCounts,
      cweCounts,
      vulnerabilities
    };
  };

  // Función para parsear reportes de ZAP
  const parseZapReport = (data) => {
    const output = data.output || '';
    const warnings = [];
    const severityCounts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0, WARNING: 0 };
    const alertCounts = {};
    
    // Extraer warnings del output
    const warnMatches = output.match(/WARN-NEW: ([^(]+)/g);
    if (warnMatches) {
      warnMatches.forEach(warn => {
        const alertType = warn.replace('WARN-NEW: ', '').split(' [')[0];
        alertCounts[alertType] = (alertCounts[alertType] || 0) + 1;
        severityCounts.WARNING++;
        
        warnings.push({
          type: alertType,
          severity: 'WARNING',
          description: getZapAlertDescription(alertType)
        });
      });
    }

    return {
      tool: 'OWASP ZAP',
      type: 'DAST',
      totalFindings: warnings.length,
      severityCounts,
      alertCounts,
      warnings,
      rawOutput: output
    };
  };

  // Función para obtener descripciones de alertas ZAP
  const getZapAlertDescription = (alertType) => {
    const descriptions = {
      'Cross-Domain JavaScript Source File Inclusion': 'Se detectó inclusión de archivos JavaScript desde dominios externos, lo que puede ser un vector de ataque.',
      'Information Disclosure - Suspicious Comments': 'Se encontraron comentarios que pueden revelar información sensible del sistema.',
      'Content Security Policy (CSP) Header Not Set': 'La aplicación no implementa Content Security Policy, lo que puede permitir ataques XSS.',
      'Non-Storable Content': 'El contenido no puede ser almacenado en caché, lo que puede afectar el rendimiento.',
      'Deprecated Feature Policy Header Set': 'Se está usando un header de política de características deprecado.',
      'Timestamp Disclosure - Unix': 'Se detectó exposición de timestamps Unix que pueden revelar información del servidor.',
      'Cross-Domain Misconfiguration': 'Configuración incorrecta de CORS que puede permitir acceso no autorizado.',
      'Modern Web Application': 'Se detectó que es una aplicación web moderna (esto es informativo).',
      'Dangerous JS Functions': 'Se detectaron funciones JavaScript peligrosas que pueden ser explotadas.',
      'Insufficient Site Isolation Against Spectre Vulnerability': 'Falta aislamiento del sitio contra vulnerabilidades Spectre.'
    };
    return descriptions[alertType] || 'Alerta de seguridad detectada por OWASP ZAP.';
  };

  const viewLog = async (result) => {
    try {
      const response = await fetch(`http://localhost:4000${result.logUrl}`);
      const content = await response.text();
      setLogContent(content);
      setViewingLog(result);
    } catch (err) {
      setError('No se pudo cargar el log: ' + err.message);
    }
  };

  const closeModal = () => {
    setViewingReport(null);
    setViewingLog(null);
    setReportContent(null);
    setLogContent(null);
    setParsedReportData(null);
  };


  const data = dashboardData;

  // Configuración de gráficos
  const toolCountChartData = {
    labels: Object.keys(data.toolCounts),
    datasets: [{
      label: 'Escaneos Ejecutados',
      data: Object.values(data.toolCounts),
      backgroundColor: ['#3b82f6', '#10b981', '#f59e0b'],
      borderColor: ['#1d4ed8', '#047857', '#d97706'],
      borderWidth: 2
    }]
  };

  const severityChartData = {
    labels: Object.keys(data.severityCounts).filter(key => data.severityCounts[key] > 0),
    datasets: [{
      data: Object.keys(data.severityCounts).filter(key => data.severityCounts[key] > 0).map(key => data.severityCounts[key]),
      backgroundColor: [
        '#ef4444', // HIGH - Red
        '#f59e0b', // MEDIUM - Orange  
        '#eab308', // LOW - Yellow
        '#8b5cf6', // WARNING - Purple
        '#6b7280'  // INFO - Gray
      ],
      borderWidth: 2,
      borderColor: '#ffffff'
    }]
  };

  const vulnerabilityTypesData = {
    labels: Object.keys(data.vulnerabilityTypes).slice(0, 10), // Top 10
    datasets: [{
      label: 'Frecuencia',
      data: Object.values(data.vulnerabilityTypes).slice(0, 10),
      backgroundColor: '#3b82f6',
      borderColor: '#1d4ed8',
      borderWidth: 1
    }]
  };

  const chartOptions = {
    responsive: true,
    plugins: {
      legend: {
        position: 'top',
      },
      title: {
        display: true,
        text: 'Distribución de Vulnerabilidades'
      }
    }
  };

  // Función para obtener recomendaciones de remediación
  const getRemediationGuide = (vulnerabilityType, severity) => {
    const guides = {
      'CSRF': {
        title: 'Cross-Site Request Forgery (CSRF)',
        description: 'Implementar tokens CSRF en formularios y requests sensibles',
        steps: [
          'Implementar middleware CSRF (csurf, csrf)',
          'Generar tokens únicos por sesión',
          'Validar tokens en todas las operaciones sensibles',
          'Usar SameSite cookies cuando sea posible'
        ],
        resources: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html',
          'https://www.npmjs.com/package/csurf'
        ]
      },
      'Path Traversal': {
        title: 'Path Traversal',
        description: 'Validar y sanitizar rutas de archivos para prevenir acceso no autorizado',
        steps: [
          'Validar nombres de archivos contra patrones seguros',
          'Usar path.resolve() con directorio base',
          'Implementar whitelist de extensiones permitidas',
          'Evitar usar entrada del usuario directamente en rutas'
        ],
        resources: [
          'https://owasp.org/www-community/attacks/Path_Traversal'
        ]
      },
      'XSS': {
        title: 'Cross-Site Scripting (XSS)',
        description: 'Sanitizar entrada del usuario y usar escape de HTML',
        steps: [
          'Usar bibliotecas de sanitización (DOMPurify)',
          'Implementar Content Security Policy (CSP)',
          'Escape HTML en templates',
          'Validar entrada del usuario en el servidor'
        ],
        resources: [
          'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'
        ]
      },
      'SQL Injection': {
        title: 'SQL Injection',
        description: 'Usar consultas preparadas y validación de entrada',
        steps: [
          'Usar consultas preparadas (prepared statements)',
          'Validar y sanitizar entrada del usuario',
          'Implementar principio de menor privilegio en DB',
          'Usar ORMs que manejen SQL de forma segura'
        ],
        resources: [
          'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'
        ]
      },
      'Memory Leak': {
        title: 'Memory Leak en Multer',
        description: 'Actualizar dependencias vulnerables a versiones seguras',
        steps: [
          'Actualizar Multer a versión 2.0.0 o superior',
          'Implementar manejo adecuado de streams',
          'Agregar timeouts para uploads',
          'Monitorear uso de memoria en producción'
        ],
        resources: [
          'https://github.com/expressjs/multer/releases',
          'https://nvd.nist.gov/vuln/detail/CVE-2025-47935'
        ]
      },
      'CSP': {
        title: 'Content Security Policy (CSP)',
        description: 'Implementar headers CSP para prevenir XSS',
        steps: [
          'Configurar CSP header en el servidor',
          'Definir sources permitidos para scripts, styles, etc.',
          'Implementar nonce o hash para scripts inline',
          'Usar report-uri para monitorear violaciones'
        ],
        resources: [
          'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP'
        ]
      }
    };

    return guides[vulnerabilityType] || {
      title: vulnerabilityType,
      description: 'Revisar documentación oficial para remediación específica',
      steps: ['Consultar documentación de seguridad', 'Implementar mejores prácticas'],
      resources: ['https://owasp.org/']
    };
  };

  return (
    <div style={{ 
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif', 
      padding: 0, 
      background: '#f8fafc',
      minHeight: '100vh'
    }}>
      {/* Header Navigation */}
      <header style={{
        background: '#1e293b',
        color: 'white',
        padding: '0 20px',
        boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
      }}>
        <div style={{ 
          maxWidth: '1400px', 
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: '60px'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 40,
              height: 40,
              background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '20px'
            }}>
              🛡️
            </div>
            <h1 style={{ 
              margin: 0, 
              fontSize: '1.5rem', 
              fontWeight: '600',
              color: 'white'
            }}>
              DevSecOps Lab - Vulnerability Manager
            </h1>
          </div>
          
          <div style={{ display: 'flex', alignItems: 'center', gap: 20 }}>
            <button 
              onClick={() => setShowWorkflowManager(true)}
              style={{
                background: 'rgba(255, 255, 255, 0.1)',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                padding: '8px 16px',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500',
                transition: 'all 0.3s ease',
                marginRight: '10px'
              }}
              onMouseOver={(e) => e.target.style.background = 'rgba(255, 255, 255, 0.2)'}
              onMouseOut={(e) => e.target.style.background = 'rgba(255, 255, 255, 0.1)'}
            >
              🚀 Workflows
            </button>
            
            <button 
              onClick={loadResults}
              style={{
                background: 'rgba(255, 255, 255, 0.1)',
                color: 'white',
                border: 'none',
                borderRadius: '6px',
                padding: '8px 16px',
                cursor: 'pointer',
                fontSize: '14px',
                fontWeight: '500',
                transition: 'all 0.3s ease'
              }}
              onMouseOver={(e) => e.target.style.background = 'rgba(255, 255, 255, 0.2)'}
              onMouseOut={(e) => e.target.style.background = 'rgba(255, 255, 255, 0.1)'}
            >
              🔄 Actualizar
            </button>
            
            <div style={{
              width: 32,
              height: 32,
              background: 'rgba(255, 255, 255, 0.1)',
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              cursor: 'pointer'
            }}>
              👤
            </div>
          </div>
        </div>
      </header>

      <div style={{ maxWidth: '1400px', margin: '0 auto', padding: '20px' }}>

        {error && (
          <div style={{ background: '#fee2e2', color: '#991b1b', padding: 12, borderRadius: 6, marginBottom: 16 }}>
            {error}
          </div>
        )}

        {/* Filtros */}
        <div style={{ marginBottom: 24, display: 'flex', gap: 16, alignItems: 'center' }}>
          <label style={{ fontWeight: 'bold' }}>Filtrar por herramienta:</label>
          <select 
            value={selectedTool} 
            onChange={(e) => setSelectedTool(e.target.value)}
            style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d1d5db' }}
          >
            <option value="all">Todas las herramientas</option>
            <option value="semgrep">Semgrep (SAST)</option>
            <option value="trivy">Trivy (SCA)</option>
            <option value="zap">OWASP ZAP (DAST)</option>
          </select>
          <button 
            onClick={loadResults}
            style={{ 
              padding: '8px 16px', 
              background: '#3b82f6', 
              color: 'white', 
              border: 'none', 
              borderRadius: 6,
              cursor: 'pointer'
            }}
          >
            🔄 Actualizar Datos
          </button>
        </div>

        {/* Métricas principales - Estilo profesional */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', 
          gap: 20, 
          marginBottom: 30 
        }}>
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700', color: '#3b82f6' }}>
                {data.totalVulnerabilities}
              </h3>
              <div style={{ fontSize: '24px' }}>📊</div>
            </div>
            <p style={{ margin: 0, fontSize: '14px', color: '#64748b', fontWeight: '500' }}>
              Total Vulnerabilities
            </p>
          </div>
          
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700', color: '#3b82f6' }}>
                {data.severityCounts.HIGH + data.severityCounts.CRITICAL || 0}
              </h3>
              <div style={{ fontSize: '24px' }}>🔥</div>
            </div>
            <p style={{ margin: 0, fontSize: '14px', color: '#64748b', fontWeight: '500' }}>
              Critical & High Vulnerabilities
            </p>
          </div>
          
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700', color: '#3b82f6' }}>
                {data.severityCounts.MEDIUM || 0}
              </h3>
              <div style={{ fontSize: '24px' }}>⚠️</div>
            </div>
            <p style={{ margin: 0, fontSize: '14px', color: '#64748b', fontWeight: '500' }}>
              Medium Vulnerabilities
            </p>
          </div>
          
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700', color: '#6b7280' }}>
                {results.length}
              </h3>
              <div style={{ fontSize: '24px' }}>🔄</div>
            </div>
            <p style={{ margin: 0, fontSize: '14px', color: '#64748b', fontWeight: '500' }}>
              Scans Executed
            </p>
          </div>
        </div>

        {/* Panel de gráficos profesional */}
        <div style={{ 
          display: 'grid', 
          gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', 
          gap: 20, 
          marginBottom: 30 
        }}>
          {/* Vulnerability Severity Summary */}
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0'
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              marginBottom: 20 
            }}>
              <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600', color: '#1f2937' }}>
                Vulnerability Severity Summary
              </h3>
              <select style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: '1px solid #d1d5db',
                fontSize: '14px',
                background: 'white'
              }}>
                <option>All</option>
                <option>Last 7 days</option>
                <option>Last 30 days</option>
              </select>
            </div>
            <Doughnut 
              data={{
                labels: Object.keys(data.severityCounts).filter(key => data.severityCounts[key] > 0),
                datasets: [{
                  data: Object.keys(data.severityCounts).filter(key => data.severityCounts[key] > 0).map(key => data.severityCounts[key]),
                  backgroundColor: [
                    '#dc2626', // CRITICAL - Red
                    '#ea580c', // HIGH - Orange
                    '#d97706', // MEDIUM - Amber
                    '#eab308', // LOW - Yellow
                    '#8b5cf6', // WARNING - Purple
                    '#6b7280'  // INFO - Gray
                  ],
                  borderWidth: 2,
                  borderColor: '#ffffff'
                }]
              }}
              options={{
                responsive: true,
                plugins: {
                  legend: {
                    position: 'bottom',
                    labels: {
                      padding: 15,
                      usePointStyle: true,
                      font: { size: 12 }
                    }
                  }
                }
              }}
            />
          </div>

          {/* Scan Results by Tool */}
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0'
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              marginBottom: 20 
            }}>
              <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600', color: '#1f2937' }}>
                Scan Results by Tool
              </h3>
              <select style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: '1px solid #d1d5db',
                fontSize: '14px',
                background: 'white'
              }}>
                <option>All</option>
                <option>Last 7 days</option>
                <option>Last 30 days</option>
              </select>
            </div>
            <Bar 
              data={{
                labels: Object.keys(data.toolCounts),
                datasets: [{
                  label: 'Scans Executed',
                  data: Object.values(data.toolCounts),
                  backgroundColor: ['#3b82f6', '#10b981', '#f59e0b'],
                  borderColor: ['#1d4ed8', '#047857', '#d97706'],
                  borderWidth: 1,
                  borderRadius: 4
                }]
              }}
              options={{
                responsive: true,
                plugins: {
                  legend: { display: false }
                },
                scales: {
                  y: {
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                  }
                }
              }}
            />
          </div>

          {/* Vulnerability Types */}
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0',
            gridColumn: 'span 2'
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              marginBottom: 20 
            }}>
              <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600', color: '#1f2937' }}>
                Top Vulnerability Types
              </h3>
              <select style={{
                padding: '6px 12px',
                borderRadius: 6,
                border: '1px solid #d1d5db',
                fontSize: '14px',
                background: 'white'
              }}>
                <option>Top 10</option>
                <option>Top 20</option>
                <option>All</option>
              </select>
            </div>
            <Bar 
              data={{
                labels: Object.keys(data.vulnerabilityTypes).slice(0, 10),
                datasets: [{
                  label: 'Count',
                  data: Object.values(data.vulnerabilityTypes).slice(0, 10),
                  backgroundColor: '#3b82f6',
                  borderColor: '#1d4ed8',
                  borderWidth: 1,
                  borderRadius: 4
                }]
              }}
              options={{
                responsive: true,
                indexAxis: 'y',
                plugins: {
                  legend: { display: false }
                },
                scales: {
                  x: {
                    beginAtZero: true,
                    ticks: { stepSize: 1 }
                  }
                }
              }}
            />
          </div>
        </div>

        {/* CVE Details Table */}
        {data.cveData.length > 0 && (
          <div style={{ 
            background: 'white',
            padding: 24, 
            borderRadius: 8, 
            boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
            border: '1px solid #e2e8f0',
            marginBottom: 30
          }}>
            <div style={{ 
              display: 'flex', 
              alignItems: 'center', 
              justifyContent: 'space-between',
              marginBottom: 20 
            }}>
              <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: '600', color: '#1f2937' }}>
                Detected CVEs
              </h3>
              <span style={{
                background: '#f3f4f6',
                color: '#6b7280',
                padding: '4px 12px',
                borderRadius: 6,
                fontSize: '0.875rem',
                fontWeight: '500'
              }}>
                {data.cveData.length} vulnerabilities
              </span>
            </div>
            
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid #e5e7eb' }}>
                    <th style={{ textAlign: 'left', padding: '12px', fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>CVE ID</th>
                    <th style={{ textAlign: 'left', padding: '12px', fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Severity</th>
                    <th style={{ textAlign: 'left', padding: '12px', fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Package</th>
                    <th style={{ textAlign: 'left', padding: '12px', fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>CVSS</th>
                    <th style={{ textAlign: 'left', padding: '12px', fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Published</th>
                    <th style={{ textAlign: 'left', padding: '12px', fontSize: '0.875rem', fontWeight: '600', color: '#374151' }}>Fix Available</th>
                  </tr>
                </thead>
                <tbody>
                  {data.cveData.slice(0, 10).map((cve, index) => (
                    <tr key={index} style={{ 
                      borderBottom: '1px solid #f3f4f6'
                    }}>
                      <td style={{ padding: '12px', fontSize: '0.875rem' }}>
                        <a href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`} 
                           target="_blank" 
                           rel="noopener noreferrer"
                           style={{ 
                             color: '#3b82f6', 
                             textDecoration: 'none',
                             fontWeight: '500'
                           }}>
                          {cve.id}
                        </a>
                      </td>
                      <td style={{ padding: '12px' }}>
                        <span style={{
                          background: cve.severity === 'HIGH' ? '#fee2e2' : cve.severity === 'MEDIUM' ? '#fef3c7' : '#f3f4f6',
                          color: cve.severity === 'HIGH' ? '#dc2626' : cve.severity === 'MEDIUM' ? '#d97706' : '#6b7280',
                          padding: '4px 8px',
                          borderRadius: 4,
                          fontSize: '0.75rem',
                          fontWeight: '600',
                          textTransform: 'uppercase'
                        }}>
                          {cve.severity}
                        </span>
                      </td>
                      <td style={{ padding: '12px', fontSize: '0.875rem', color: '#374151' }}>
                        {cve.package} v{cve.version}
                      </td>
                      <td style={{ padding: '12px', fontSize: '0.875rem', color: '#6b7280' }}>
                        {cve.cvss || 'N/A'}
                      </td>
                      <td style={{ padding: '12px', fontSize: '0.875rem', color: '#6b7280' }}>
                        {cve.published}
                      </td>
                      <td style={{ padding: '12px', fontSize: '0.875rem' }}>
                        {cve.fixedVersion ? (
                          <span style={{ color: '#059669', fontWeight: '500' }}>
                            v{cve.fixedVersion}
                          </span>
                        ) : (
                          <span style={{ color: '#dc2626' }}>No fix</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              
              {data.cveData.length > 10 && (
                <div style={{ 
                  padding: '12px', 
                  textAlign: 'center', 
                  color: '#6b7280', 
                  fontSize: '0.875rem',
                  borderTop: '1px solid #e5e7eb'
                }}>
                  Showing 10 of {data.cveData.length} vulnerabilities
                </div>
              )}
            </div>
          </div>
        )}

        {/* Guías de Remediación */}
        <div style={{ 
          background: 'rgba(255, 255, 255, 0.95)',
          backdropFilter: 'blur(10px)',
          padding: 30, 
          borderRadius: 20, 
          boxShadow: '0 20px 40px rgba(0,0,0,0.1)',
          border: '1px solid rgba(255, 255, 255, 0.2)',
          marginBottom: 40 
        }}>
          <div style={{ display: 'flex', alignItems: 'center', marginBottom: 25 }}>
            <div style={{
              width: 50,
              height: 50,
              background: 'linear-gradient(135deg, #26a69a, #00acc1)',
              borderRadius: '15px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: 15,
              fontSize: '24px'
            }}>🛠️</div>
            <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700', color: '#1f2937' }}>
              Guías de Remediación
            </h3>
          </div>
          <div style={{ display: 'grid', gap: 20 }}>
            {Object.keys(data.vulnerabilityTypes).slice(0, 5).map((vulnType, index) => {
              const guide = getRemediationGuide(vulnType, 'HIGH');
              return (
                <div key={index} style={{ 
                  border: '1px solid rgba(229, 231, 235, 0.5)', 
                  borderRadius: 15, 
                  padding: 25,
                  background: 'linear-gradient(135deg, rgba(248, 250, 252, 0.8), rgba(241, 245, 249, 0.8))',
                  backdropFilter: 'blur(5px)',
                  transition: 'all 0.3s ease',
                  cursor: 'pointer'
                }}>
                  <h4 style={{ 
                    margin: '0 0 12px 0', 
                    color: '#1f2937',
                    fontSize: '1.3rem',
                    fontWeight: '600'
                  }}>
                    {guide.title}
                  </h4>
                  <p style={{ 
                    margin: '0 0 16px 0', 
                    color: '#4b5563',
                    fontSize: '1rem',
                    lineHeight: '1.5'
                  }}>
                    {guide.description}
                  </p>
                  <div style={{ marginBottom: 16 }}>
                    <strong style={{ color: '#1f2937', fontSize: '1rem' }}>📋 Pasos de Remediación:</strong>
                    <ol style={{ margin: '12px 0', paddingLeft: 25 }}>
                      {guide.steps.map((step, i) => (
                        <li key={i} style={{ 
                          marginBottom: 8, 
                          color: '#374151',
                          fontSize: '0.95rem',
                          lineHeight: '1.4'
                        }}>
                          {step}
                        </li>
                      ))}
                    </ol>
                  </div>
                  <div>
                    <strong style={{ color: '#1f2937', fontSize: '1rem' }}>🔗 Recursos:</strong>
                    <ul style={{ margin: '12px 0', paddingLeft: 25 }}>
                      {guide.resources.map((resource, i) => (
                        <li key={i} style={{ marginBottom: 6 }}>
                          <a 
                            href={resource} 
                            target="_blank" 
                            rel="noopener noreferrer" 
                            style={{ 
                              color: '#3b82f6',
                              textDecoration: 'none',
                              fontSize: '0.9rem',
                              fontWeight: '500'
                            }}
                          >
                            📖 {resource}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Execute Scans */}
        <div style={{ 
          background: 'white',
          padding: 24, 
          borderRadius: 8, 
          boxShadow: '0 1px 3px rgba(0,0,0,0.1)',
          border: '1px solid #e2e8f0',
          marginBottom: 30
        }}>
          <h3 style={{ margin: '0 0 20px 0', fontSize: '1.25rem', fontWeight: '600', color: '#1f2937' }}>
            Execute Security Scans
          </h3>
          
          {labs.length === 0 ? (
            <p style={{ color: '#6b7280', margin: 0 }}>No labs available.</p>
          ) : (
            <div style={{ display: 'grid', gap: 16 }}>
              {labs.map(lab => (
                <div key={lab.id} style={{ 
                  border: '1px solid #e5e7eb', 
                  borderRadius: 8, 
                  padding: 20,
                  background: '#f9fafb'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <div>
                      <h4 style={{ margin: '0 0 4px 0', fontSize: '1.125rem', fontWeight: '600', color: '#1f2937' }}>
                        {lab.name}
                      </h4>
                      <p style={{ margin: 0, fontSize: '0.875rem', color: '#6b7280' }}>{lab.id}</p>
                    </div>
                    <div style={{ display: 'flex', gap: 12 }}>
                      <button 
                        onClick={() => runJob(lab.id, 'semgrep')}
                        disabled={runningJobs.includes('semgrep')}
                        style={{ 
                          padding: '10px 16px', 
                          background: runningJobs.includes('semgrep') ? '#f3f4f6' : '#3b82f6', 
                          color: runningJobs.includes('semgrep') ? '#6b7280' : 'white', 
                          border: runningJobs.includes('semgrep') ? '1px solid #d1d5db' : 'none', 
                          borderRadius: 6,
                          cursor: runningJobs.includes('semgrep') ? 'not-allowed' : 'pointer',
                          fontSize: '0.875rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6
                        }}
                      >
                        🔍 {runningJobs.includes('semgrep') ? 'Running...' : 'SAST'}
                      </button>
                      <button 
                        onClick={() => runJob(lab.id, 'trivy')}
                        disabled={runningJobs.includes('trivy')}
                        style={{ 
                          padding: '10px 16px', 
                          background: runningJobs.includes('trivy') ? '#f3f4f6' : '#10b981', 
                          color: runningJobs.includes('trivy') ? '#6b7280' : 'white', 
                          border: runningJobs.includes('trivy') ? '1px solid #d1d5db' : 'none', 
                          borderRadius: 6,
                          cursor: runningJobs.includes('trivy') ? 'not-allowed' : 'pointer',
                          fontSize: '0.875rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6
                        }}
                      >
                        📦 {runningJobs.includes('trivy') ? 'Running...' : 'SCA'}
                      </button>
                      <button 
                        onClick={() => runJob(lab.id, 'zap')}
                        disabled={runningJobs.includes('zap')}
                        style={{ 
                          padding: '10px 16px', 
                          background: runningJobs.includes('zap') ? '#f3f4f6' : '#f59e0b', 
                          color: runningJobs.includes('zap') ? '#6b7280' : 'white', 
                          border: runningJobs.includes('zap') ? '1px solid #d1d5db' : 'none', 
                          borderRadius: 6,
                          cursor: runningJobs.includes('zap') ? 'not-allowed' : 'pointer',
                          fontSize: '0.875rem',
                          fontWeight: '500',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6
                        }}
                      >
                        🌐 {runningJobs.includes('zap') ? 'Running...' : 'DAST'}
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
          <div style={{ marginTop: 16, padding: '12px', background: '#f3f4f6', borderRadius: 6, fontSize: '0.875rem', color: '#6b7280' }}>
            {running ? `🔄 Running ${running.job} for ${running.labId}...` : 'No scans running'}
          </div>
        </div>

        {/* Resultados detallados */}
        <div style={{ background: 'white', padding: 20, borderRadius: 8, boxShadow: '0 1px 3px rgba(0,0,0,0.1)' }}>
          <h3 style={{ marginTop: 0 }}>📊 Resultados Detallados</h3>
          {results.length === 0 ? (
            <p style={{ color: '#6b7280' }}>No hay resultados disponibles. Ejecuta un escaneo para generar reportes.</p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: 12 }}>
                <thead>
                  <tr style={{ background: '#e5e7eb', textAlign: 'left' }}>
                    <th style={{ padding: '12px' }}>Herramienta</th>
                    <th style={{ padding: '12px' }}>Laboratorio</th>
                    <th style={{ padding: '12px' }}>Última ejecución</th>
                    <th style={{ padding: '12px' }}>Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map(result => (
                    <tr key={result.file} style={{ borderBottom: '1px solid #e5e7eb' }}>
                      <td style={{ padding: '12px' }}>
                        <span style={{
                          padding: '4px 8px',
                          borderRadius: 4,
                          fontSize: '0.8rem',
                          fontWeight: 'bold',
                          background: result.job === 'semgrep' ? '#3b82f6' : result.job === 'trivy' ? '#10b981' : '#f59e0b',
                          color: 'white'
                        }}>
                          {result.job.toUpperCase()}
                        </span>
                      </td>
                      <td style={{ padding: '12px' }}>{result.labId}</td>
                      <td style={{ padding: '12px' }}>
                        {new Date(result.updatedAt).toLocaleString()}
                      </td>
                      <td style={{ padding: '12px' }}>
                        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                          <button 
                            onClick={() => viewReport(result)}
                            style={{ 
                              padding: '6px 12px', 
                              fontSize: '12px', 
                              background: '#3b82f6', 
                              color: 'white', 
                              border: 'none', 
                              borderRadius: '4px',
                              cursor: 'pointer'
                            }}
                          >
                            📄 Ver Reporte
                          </button>
                          {result.logUrl && (
                            <button 
                              onClick={() => viewLog(result)}
                              style={{ 
                                padding: '6px 12px', 
                                fontSize: '12px', 
                                background: '#f59e0b', 
                                color: 'white', 
                                border: 'none', 
                                borderRadius: '4px',
                                cursor: 'pointer'
                              }}
                            >
                              📋 Ver Log
                            </button>
                          )}
                          <a 
                            href={`http://localhost:4000${result.url}`} 
                            target="_blank" 
                            rel="noreferrer"
                            style={{ 
                              padding: '6px 12px', 
                              fontSize: '12px', 
                              background: '#10b981', 
                              color: 'white', 
                              border: 'none', 
                              borderRadius: '4px',
                              textDecoration: 'none',
                              display: 'inline-block'
                            }}
                          >
                            ⬇️ Descargar
                          </a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Modal de Reporte Interactivo */}
        {viewingReport && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px'
          }}>
            <div style={{
              background: 'white',
              borderRadius: '20px',
              padding: '0',
              maxWidth: '95vw',
              maxHeight: '95vh',
              overflow: 'auto',
              position: 'relative',
              boxShadow: '0 25px 50px rgba(0,0,0,0.3)'
            }}>
              {/* Header del Modal */}
              <div style={{
                background: 'linear-gradient(135deg, #667eea, #764ba2)',
                color: 'white',
                padding: '25px',
                borderRadius: '20px 20px 0 0',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 15 }}>
                  <div style={{
                    width: 50,
                    height: 50,
                    background: 'rgba(255, 255, 255, 0.2)',
                    borderRadius: '12px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '24px'
                  }}>
                    {viewingReport.job === 'semgrep' ? '🔍' : viewingReport.job === 'trivy' ? '📦' : '🌐'}
                  </div>
                  <div>
                    <h2 style={{ margin: 0, fontSize: '1.8rem', fontWeight: '700' }}>
                      {parsedReportData ? `${parsedReportData.tool} - ${parsedReportData.type}` : `${viewingReport.job.toUpperCase()} - Reporte`}
                    </h2>
                    <p style={{ margin: 4, opacity: 0.9, fontSize: '1rem' }}>
                      {viewingReport.labId} • {new Date(viewingReport.updatedAt).toLocaleString()}
                    </p>
                  </div>
                </div>
                <button 
                  onClick={closeModal}
                  style={{
                    background: 'rgba(255, 255, 255, 0.2)',
                    color: 'white',
                    border: 'none',
                    borderRadius: '12px',
                    padding: '12px 20px',
                    cursor: 'pointer',
                    fontSize: '16px',
                    fontWeight: '600',
                    transition: 'all 0.3s ease'
                  }}
                  onMouseOver={(e) => e.target.style.background = 'rgba(255, 255, 255, 0.3)'}
                  onMouseOut={(e) => e.target.style.background = 'rgba(255, 255, 255, 0.2)'}
                >
                  ✕ Cerrar
                </button>
              </div>

              {/* Contenido del Modal */}
              <div style={{ padding: '30px' }}>
                {parsedReportData && parsedReportData.totalFindings > 0 ? (
                  <>
                    {/* Métricas Principales */}
                    <div style={{ 
                      display: 'grid', 
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', 
                      gap: 20, 
                      marginBottom: 30 
                    }}>
                      <div style={{
                        background: 'linear-gradient(135deg, #ff6b6b, #ee5a24)',
                        color: 'white',
                        padding: 20,
                        borderRadius: 15,
                        textAlign: 'center',
                        boxShadow: '0 10px 25px rgba(255, 107, 107, 0.3)'
                      }}>
                        <div style={{ fontSize: '2rem', marginBottom: 8 }}>📊</div>
                        <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700' }}>
                          {parsedReportData.totalFindings}
                        </h3>
                        <p style={{ margin: 4, opacity: 0.9 }}>Hallazgos Totales</p>
                      </div>
                  
                  <div style={{
                    background: 'linear-gradient(135deg, #ff4757, #c44569)',
                    color: 'white',
                    padding: 20,
                    borderRadius: 15,
                    textAlign: 'center',
                    boxShadow: '0 10px 25px rgba(255, 71, 87, 0.3)'
                  }}>
                    <div style={{ fontSize: '2rem', marginBottom: 8 }}>🔥</div>
                    <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700' }}>
                      {parsedReportData.severityCounts.HIGH + parsedReportData.severityCounts.CRITICAL || 0}
                    </h3>
                    <p style={{ margin: 4, opacity: 0.9 }}>Críticas</p>
                  </div>
                  
                  <div style={{
                    background: 'linear-gradient(135deg, #ffa726, #ff9800)',
                    color: 'white',
                    padding: 20,
                    borderRadius: 15,
                    textAlign: 'center',
                    boxShadow: '0 10px 25px rgba(255, 167, 38, 0.3)'
                  }}>
                    <div style={{ fontSize: '2rem', marginBottom: 8 }}>⚠️</div>
                    <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700' }}>
                      {parsedReportData.severityCounts.MEDIUM || 0}
                    </h3>
                    <p style={{ margin: 4, opacity: 0.9 }}>Medias</p>
                  </div>
                  
                  <div style={{
                    background: 'linear-gradient(135deg, #26a69a, #00acc1)',
                    color: 'white',
                    padding: 20,
                    borderRadius: 15,
                    textAlign: 'center',
                    boxShadow: '0 10px 25px rgba(38, 166, 154, 0.3)'
                  }}>
                    <div style={{ fontSize: '2rem', marginBottom: 8 }}>📈</div>
                    <h3 style={{ margin: 0, fontSize: '2rem', fontWeight: '700' }}>
                      {Object.keys(parsedReportData.severityCounts).filter(k => parsedReportData.severityCounts[k] > 0).length}
                    </h3>
                    <p style={{ margin: 4, opacity: 0.9 }}>Niveles de Severidad</p>
                  </div>
                </div>

                {/* Gráfico de Severidad */}
                <div style={{ 
                  background: '#f8fafc', 
                  padding: 20, 
                  borderRadius: 15, 
                  marginBottom: 30,
                  border: '1px solid #e2e8f0'
                }}>
                  <h3 style={{ margin: '0 0 20px 0', color: '#1f2937', fontSize: '1.25rem' }}>
                    📊 Distribución por Severidad
                  </h3>
                  <div style={{ 
                    maxWidth: '400px', 
                    maxHeight: '400px', 
                    margin: '0 auto',
                    position: 'relative'
                  }}>
                    <Doughnut 
                      data={{
                        labels: Object.keys(parsedReportData.severityCounts).filter(key => parsedReportData.severityCounts[key] > 0),
                        datasets: [{
                          data: Object.keys(parsedReportData.severityCounts).filter(key => parsedReportData.severityCounts[key] > 0).map(key => parsedReportData.severityCounts[key]),
                          backgroundColor: [
                            '#dc2626', // CRITICAL - Dark Red
                            '#ef4444', // HIGH - Red
                            '#f59e0b', // MEDIUM - Orange  
                            '#eab308', // LOW - Yellow
                            '#8b5cf6', // WARNING - Purple
                            '#6b7280'  // INFO - Gray
                          ],
                          borderWidth: 2,
                          borderColor: '#ffffff'
                        }]
                      }}
                      options={{
                        responsive: true,
                        maintainAspectRatio: true,
                        aspectRatio: 1,
                        plugins: {
                          legend: {
                            position: 'bottom',
                            labels: {
                              padding: 15,
                              usePointStyle: true,
                              font: { size: 12 }
                            }
                          }
                        },
                        layout: {
                          padding: {
                            top: 10,
                            bottom: 10
                          }
                        }
                      }}
                    />
                  </div>
                </div>

                {/* Detalles de Hallazgos */}
                <div style={{ marginBottom: 30 }}>
                  <h3 style={{ margin: '0 0 20px 0', color: '#1f2937', fontSize: '1.5rem' }}>
                    🔍 Detalles de Hallazgos
                  </h3>
                  <div style={{ maxHeight: '400px', overflowY: 'auto' }}>
                    {viewingReport.job === 'semgrep' && parsedReportData.findings && (
                      <div style={{ display: 'grid', gap: 15 }}>
                        {parsedReportData.findings.slice(0, 20).map((finding, index) => (
                          <div key={index} style={{
                            border: '1px solid #e5e7eb',
                            borderRadius: 12,
                            padding: 20,
                            background: finding.severity === 'HIGH' || finding.severity === 'ERROR'
                              ? 'linear-gradient(135deg, rgba(254, 242, 242, 0.8), rgba(252, 231, 243, 0.8))'
                              : finding.severity === 'MEDIUM'
                              ? 'linear-gradient(135deg, rgba(255, 251, 235, 0.8), rgba(254, 249, 195, 0.8))'
                              : 'linear-gradient(135deg, rgba(249, 250, 251, 0.8), rgba(243, 244, 246, 0.8))'
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 12 }}>
                              <div>
                                <h4 style={{ margin: 0, color: '#1f2937', fontSize: '1.1rem' }}>
                                  {finding.rule}
                                </h4>
                                <p style={{ margin: 4, color: '#6b7280', fontSize: '0.9rem' }}>
                                  📁 {finding.file}:{finding.line}:{finding.column}
                                </p>
                              </div>
                              <span style={{
                                padding: '6px 12px',
                                borderRadius: 20,
                                fontSize: '0.8rem',
                                fontWeight: 'bold',
                                background: finding.severity === 'HIGH' || finding.severity === 'ERROR'
                                  ? 'linear-gradient(135deg, #ff4757, #c44569)'
                                  : finding.severity === 'MEDIUM'
                                  ? 'linear-gradient(135deg, #ffa726, #ff9800)'
                                  : 'linear-gradient(135deg, #26a69a, #00acc1)',
                                color: 'white'
                              }}>
                                {finding.severity}
                              </span>
                            </div>
                            <p style={{ margin: '8px 0', color: '#374151', fontSize: '0.95rem' }}>
                              {finding.message}
                            </p>
                            {finding.description && (
                              <p style={{ margin: '8px 0', color: '#6b7280', fontSize: '0.9rem', fontStyle: 'italic' }}>
                                💡 {finding.description}
                              </p>
                            )}
                          </div>
                        ))}
                      </div>
                    )}

                    {viewingReport.job === 'trivy' && parsedReportData.vulnerabilities && (
                      <div style={{ display: 'grid', gap: 15 }}>
                        {parsedReportData.vulnerabilities.slice(0, 20).map((vuln, index) => (
                          <div key={index} style={{
                            border: '1px solid #e5e7eb',
                            borderRadius: 12,
                            padding: 20,
                            background: vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH'
                              ? 'linear-gradient(135deg, rgba(254, 242, 242, 0.8), rgba(252, 231, 243, 0.8))'
                              : vuln.severity === 'MEDIUM'
                              ? 'linear-gradient(135deg, rgba(255, 251, 235, 0.8), rgba(254, 249, 195, 0.8))'
                              : 'linear-gradient(135deg, rgba(249, 250, 251, 0.8), rgba(243, 244, 246, 0.8))'
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 12 }}>
                              <div>
                                <h4 style={{ margin: 0, color: '#1f2937', fontSize: '1.1rem' }}>
                                  {vuln.id}
                                </h4>
                                <p style={{ margin: 4, color: '#6b7280', fontSize: '0.9rem' }}>
                                  📦 {vuln.package} v{vuln.version}
                                </p>
                              </div>
                              <span style={{
                                padding: '6px 12px',
                                borderRadius: 20,
                                fontSize: '0.8rem',
                                fontWeight: 'bold',
                                background: vuln.severity === 'CRITICAL'
                                  ? 'linear-gradient(135deg, #dc2626, #991b1b)'
                                  : vuln.severity === 'HIGH'
                                  ? 'linear-gradient(135deg, #ff4757, #c44569)'
                                  : vuln.severity === 'MEDIUM'
                                  ? 'linear-gradient(135deg, #ffa726, #ff9800)'
                                  : 'linear-gradient(135deg, #26a69a, #00acc1)',
                                color: 'white'
                              }}>
                                {vuln.severity}
                              </span>
                            </div>
                            <p style={{ margin: '8px 0', color: '#374151', fontSize: '0.95rem' }}>
                              {vuln.title}
                            </p>
                            <p style={{ margin: '8px 0', color: '#6b7280', fontSize: '0.9rem' }}>
                              {vuln.description}
                            </p>
                            <div style={{ display: 'flex', gap: 15, fontSize: '0.85rem', color: '#6b7280', flexWrap: 'wrap' }}>
                              <span>🎯 CVSS: {vuln.cvss}</span>
                              {vuln.fixedVersion && <span>✅ Fix: v{vuln.fixedVersion}</span>}
                              {vuln.cwe && <span>🔗 CWE: {vuln.cwe}</span>}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                    {viewingReport.job === 'zap' && parsedReportData.warnings && (
                      <div style={{ display: 'grid', gap: 15 }}>
                        {parsedReportData.warnings.slice(0, 20).map((warning, index) => (
                          <div key={index} style={{
                            border: '1px solid #e5e7eb',
                            borderRadius: 12,
                            padding: 20,
                            background: 'linear-gradient(135deg, rgba(255, 251, 235, 0.8), rgba(254, 249, 195, 0.8))'
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 12 }}>
                              <h4 style={{ margin: 0, color: '#1f2937', fontSize: '1.1rem' }}>
                                {warning.type}
                              </h4>
                              <span style={{
                                padding: '6px 12px',
                                borderRadius: 20,
                                fontSize: '0.8rem',
                                fontWeight: 'bold',
                                background: 'linear-gradient(135deg, #f59e0b, #d97706)',
                                color: 'white'
                              }}>
                                WARNING
                              </span>
                            </div>
                            <p style={{ margin: '8px 0', color: '#374151', fontSize: '0.95rem' }}>
                              {warning.description}
                            </p>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                    {/* Vista Raw (opcional) */}
                    <details style={{ marginTop: 20 }}>
                      <summary style={{ 
                        cursor: 'pointer', 
                        padding: 15, 
                        background: '#f8fafc', 
                        borderRadius: 10,
                        border: '1px solid #e2e8f0',
                        fontWeight: '600',
                        color: '#374151'
                      }}>
                        📄 Ver Reporte Raw
                      </summary>
                      <pre style={{
                        background: '#1f2937',
                        color: '#f9fafb',
                        padding: 20,
                        borderRadius: 10,
                        fontSize: '12px',
                        overflow: 'auto',
                        maxHeight: '300px',
                        marginTop: 10,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        fontFamily: 'Monaco, Consolas, "Courier New", monospace'
                      }}>
                        {reportContent}
                      </pre>
                    </details>
                  </>
                ) : (
                  /* Vista Raw por defecto cuando no hay datos parseados */
                  <div>
                    <h3 style={{ margin: '0 0 20px 0', color: '#1f2937', fontSize: '1.5rem' }}>
                      📄 Reporte Raw
                    </h3>
                    <pre style={{
                      background: '#1f2937',
                      color: '#f9fafb',
                      padding: 20,
                      borderRadius: 10,
                      fontSize: '12px',
                      overflow: 'auto',
                      maxHeight: '60vh',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-word',
                      fontFamily: 'Monaco, Consolas, "Courier New", monospace'
                    }}>
                      {reportContent}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {viewingLog && (
          <div style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000
          }}>
            <div style={{
              background: 'white',
              borderRadius: '8px',
              padding: '20px',
              maxWidth: '80vw',
              maxHeight: '80vh',
              overflow: 'auto',
              position: 'relative'
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '16px',
                borderBottom: '1px solid #e5e7eb',
                paddingBottom: '12px'
              }}>
                <h3 style={{ margin: 0 }}>
                  Log: {viewingLog.labId} - {viewingLog.job}
                </h3>
                <button 
                  onClick={closeModal}
                  style={{
                    background: '#ef4444',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '8px 12px',
                    cursor: 'pointer'
                  }}
                >
                  Cerrar
                </button>
              </div>
              <pre style={{
                background: '#1f2937',
                color: '#f9fafb',
                border: '1px solid #374151',
                borderRadius: '4px',
                padding: '16px',
                fontSize: '12px',
                overflow: 'auto',
                maxHeight: '60vh',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: 'Monaco, Consolas, "Courier New", monospace'
              }}>
                {logContent}
              </pre>
            </div>
          </div>
        )}
      </div>
        {/* Workflow Manager Modal */}
        <WorkflowManager 
          isOpen={showWorkflowManager} 
          onClose={() => setShowWorkflowManager(false)} 
        />
      </div>
    );
  };
  
  export default SecurityDashboard;
