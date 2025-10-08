
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const { promisify } = require('util');

const execAsync = promisify(exec);

const app = express();
app.use(express.json());

// Configurar CORS para permitir peticiones desde el frontend
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(200);
  } else {
    next();
  }
});

const RESULTS_DIR = path.join(__dirname, 'results');
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR);

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', services: ['postgres','minio','juice-shop','scanners'] });
});

app.get('/api/labs', (req, res) => {
  res.json([{ id: 'juice-shop', name: 'OWASP Juice Shop' }]);
});

// Run a scanner job: semgrep, trivy, zap
app.post('/api/labs/:id/run', async (req, res) => {
  const labId = req.params.id;
  const job = req.body.job; // e.g., "semgrep", "trivy", "zap"
  const baseName = `${labId}_${job}`;
  const outFile = path.join(RESULTS_DIR, `${baseName}.json`);
  const logsFile = path.join(RESULTS_DIR, `${baseName}.log`);

  try {
    let command = '';
    let logContent = '';

    if (job === 'semgrep') {
      // Ejecutar Semgrep directamente en el contenedor
      command = `docker exec interactive-devsecops-lab-semgrep-1 semgrep --config=auto --json /src/test-app.js /src/index.js`;
      logContent = `Ejecutando Semgrep SAST scan en ${labId}...\n`;
    } else if (job === 'trivy') {
      // Ejecutar Trivy directamente en el contenedor
      command = `docker exec interactive-devsecops-lab-trivy-1 trivy fs --format json /src`;
      logContent = `Ejecutando Trivy SCA scan en ${labId}...\n`;
    } else if (job === 'zap') {
      // Ejecutar ZAP directamente en el contenedor
      command = `docker exec interactive-devsecops-lab-zap-1 zap-baseline.py -t http://juice-shop:3000 -s`;
      logContent = `Ejecutando OWASP ZAP DAST scan en ${labId}...\n`;
    } else {
      return res.status(400).json({ error: 'Unknown job' });
    }

    // Ejecutar el comando y capturar la salida
    logContent += `Comando: ${command}\n`;
    logContent += `Iniciando ejecución...\n`;

    const { stdout, stderr } = await execAsync(command).catch(error => {
      // ZAP devuelve exit code 2 cuando encuentra warnings, pero eso es normal
      if (job === 'zap' && error.code === 2) {
        return { stdout: error.stdout || '', stderr: error.stderr || '' };
      }
      throw error;
    });
    
    logContent += `Salida estándar:\n${stdout}\n`;
    if (stderr) {
      logContent += `Salida de error:\n${stderr}\n`;
    }
    logContent += `Ejecución completada.\n`;

    // Guardar el log
    fs.writeFileSync(logsFile, logContent);

    // Procesar y guardar el resultado JSON
    let resultContent = '';
    if (job === 'semgrep') {
      try {
        const semgrepResult = JSON.parse(stdout);
        resultContent = JSON.stringify(semgrepResult, null, 2);
      } catch (e) {
        resultContent = JSON.stringify({
          error: "Failed to parse Semgrep output",
          raw_output: stdout,
          stderr: stderr
        }, null, 2);
      }
    } else if (job === 'trivy') {
      try {
        const trivyResult = JSON.parse(stdout);
        resultContent = JSON.stringify(trivyResult, null, 2);
      } catch (e) {
        resultContent = JSON.stringify({
          error: "Failed to parse Trivy output",
          raw_output: stdout,
          stderr: stderr
        }, null, 2);
      }
    } else if (job === 'zap') {
      // ZAP genera salida directa en texto
      resultContent = JSON.stringify({
        tool: "OWASP ZAP",
        target: "http://juice-shop:3000",
        scan_type: "DAST",
        output: stdout,
        errors: stderr
      }, null, 2);
    }

    fs.writeFileSync(outFile, resultContent);

    return res.json({
      status: 'completed',
      job,
      resultFile: `${baseName}.json`,
      logFile: `${baseName}.log`,
      resultUrl: `/api/results/${baseName}.json`,
      logUrl: `/api/results/${baseName}.log`
    });

  } catch (error) {
    const errorLog = `Error ejecutando ${job}: ${error.message}\n${error.stack}`;
    fs.writeFileSync(logsFile, errorLog);
    
    const errorResult = JSON.stringify({
      error: error.message,
      job: job,
      labId: labId
    }, null, 2);
    
    fs.writeFileSync(outFile, errorResult);

    return res.status(500).json({
      status: 'error',
      job,
      error: error.message,
      resultFile: `${baseName}.json`,
      logFile: `${baseName}.log`,
      resultUrl: `/api/results/${baseName}.json`,
      logUrl: `/api/results/${baseName}.log`
    });
  }
});

app.get('/api/results/:file', (req, res) => {
  const file = req.params.file;
  const p = path.join(RESULTS_DIR, file);
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'file not found' });
  res.sendFile(p);
});

app.get('/api/results', (req, res) => {
  const files = fs.readdirSync(RESULTS_DIR)
    .filter(name => name.endsWith('.json'))
    .map(name => {
      const [labId, job] = name.replace('.json', '').split('_');
      const stats = fs.statSync(path.join(RESULTS_DIR, name));
      const logFile = `${labId}_${job}.log`;
      const logPath = path.join(RESULTS_DIR, logFile);
      const hasLog = fs.existsSync(logPath);
      return {
        file: name,
        labId,
        job,
        updatedAt: stats.mtime,
        url: `/api/results/${name}`,
        logFile: hasLog ? logFile : null,
        logUrl: hasLog ? `/api/results/${logFile}` : null
      };
    });
  res.json(files);
});

// Endpoints para workflow templates
app.get('/api/workflows/templates', (req, res) => {
  const templates = {
    github: {
      basic: {
        name: 'Basic Security Scan',
        description: 'Ejecuta Semgrep y Trivy en cada push',
        tools: ['semgrep', 'trivy'],
        triggers: ['push']
      },
      comprehensive: {
        name: 'Comprehensive Security Scan',
        description: 'Ejecuta todas las herramientas con notificaciones',
        tools: ['semgrep', 'trivy', 'zap'],
        triggers: ['push', 'pull_request', 'schedule']
      },
      nightly: {
        name: 'Nightly Security Audit',
        description: 'Escaneo completo todas las noches',
        tools: ['semgrep', 'trivy', 'zap'],
        triggers: ['schedule'],
        schedule: '0 2 * * *'
      }
    },
    azure: {
      basic: {
        name: 'Basic Security Pipeline',
        description: 'Pipeline básico de seguridad con Semgrep y Trivy',
        tools: ['semgrep', 'trivy'],
        triggers: ['push']
      },
      enterprise: {
        name: 'Enterprise Security Pipeline',
        description: 'Pipeline completo para entornos enterprise',
        tools: ['semgrep', 'trivy', 'zap'],
        triggers: ['push', 'pull_request', 'schedule']
      }
    }
  };
  
  res.json(templates);
});

app.post('/api/workflows/generate', (req, res) => {
  const { platform, config } = req.body;
  
  if (platform === 'github') {
    const workflow = generateGitHubWorkflow(config);
    res.json({ 
      platform: 'github',
      filename: '.github/workflows/security-scan.yml',
      content: workflow
    });
  } else if (platform === 'azure') {
    const pipeline = generateAzureDevOpsPipeline(config);
    res.json({ 
      platform: 'azure',
      filename: 'azure-pipelines-security.yml',
      content: pipeline
    });
  } else {
    res.status(400).json({ error: 'Platform not supported' });
  }
});

function generateGitHubWorkflow(config) {
  const { name, trigger, branches, tools, schedule, notifications } = config;
  
  return `name: ${name}

on:
  ${trigger}:
    branches: [ ${branches.map(b => `'${b}'`).join(', ')} ]
  schedule:
    - cron: '${schedule}'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '20'
        cache: 'npm'
        
    - name: Install dependencies
      run: npm ci
      
${tools.semgrep ? `    - name: Run Semgrep SAST
      uses: returntocorp/semgrep-action@v1
      with:
        config: >-
          p/security-audit
          p/secrets
          p/owasp-top-ten
        generateSarif: "1"
        
    - name: Upload Semgrep SARIF
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: semgrep.sarif` : ''}

${tools.trivy ? `    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        scan-ref: '.'
        format: 'sarif'
        output: 'trivy-results.sarif'
        
    - name: Upload Trivy SARIF
      uses: github/codeql-action/upload-sarif@v3
      if: always()
      with:
        sarif_file: 'trivy-results.sarif'` : ''}

${tools.zap ? `    - name: Run OWASP ZAP baseline scan
      uses: zaproxy/action-baseline@v0.9.0
      with:
        target: '\${{ github.server_url }}/\${{ github.repository }}'
        rules_file_name: '.zap/rules.tsv'
        cmd_options: '-a'` : ''}

${notifications.slack ? `    - name: Notify Slack
      if: failure()
      uses: 8398a7/action-slack@v3
      with:
        status: failure
        channel: '#security'
        webhook_url: \${{ secrets.SLACK_WEBHOOK }}
      env:
        SLACK_WEBHOOK_URL: \${{ secrets.SLACK_WEBHOOK }}` : ''}

${notifications.github ? `    - name: Create Security Report
      if: always()
      uses: actions/github-script@v7
      with:
        script: |
          const fs = require('fs');
          const results = {
            timestamp: new Date().toISOString(),
            workflow: '\${{ github.workflow }}',
            run_id: '\${{ github.run_id }}',
            status: '\${{ job.status }}',
            tools: {
              semgrep: ${tools.semgrep},
              trivy: ${tools.trivy},
              zap: ${tools.zap}
            }
          };
          
          fs.writeFileSync('security-report.json', JSON.stringify(results, null, 2));
          
    - name: Upload Security Report
      uses: actions/upload-artifact@v4
      if: always()
      with:
        name: security-report
        path: security-report.json` : ''}
`;
}

function generateAzureDevOpsPipeline(config) {
  const { name, trigger, branches, tools, schedule, notifications } = config;
  
  return `trigger:
  branches:
    include:
${branches.map(b => `    - ${b}`).join('\n')}

schedules:
- cron: "${schedule}"
  displayName: Daily Security Scan
  branches:
    include:
      - main

variables:
  nodeVersion: '20.x'

stages:
- stage: SecurityScan
  displayName: 'Security Scanning'
  jobs:
  - job: ScanJob
    displayName: 'Run Security Tools'
    pool:
      vmImage: 'ubuntu-latest'
    
    steps:
    - task: NodeTool@0
      displayName: 'Use Node.js \\$(nodeVersion)'
      inputs:
        versionSpec: '\\$(nodeVersion)'
    
    - task: Npm@1
      displayName: 'npm install'
      inputs:
        command: 'ci'
        
${tools.semgrep ? `    - script: |
        docker run --rm -v "\\$(pwd):/src" returntocorp/semgrep:latest semgrep --config=auto --json /src > semgrep-results.json
      displayName: 'Run Semgrep SAST'
      continueOnError: true
      
    - task: PublishTestResults@2
      displayName: 'Publish Semgrep Results'
      inputs:
        testResultsFiles: 'semgrep-results.json'
        testRunTitle: 'Semgrep Security Scan'
      condition: always()` : ''}

${tools.trivy ? `    - script: |
        docker run --rm -v "\\$(pwd):/src" aquasec/trivy:latest fs --format json /src > trivy-results.json
      displayName: 'Run Trivy SCA'
      continueOnError: true
      
    - task: PublishTestResults@2
      displayName: 'Publish Trivy Results'
      inputs:
        testResultsFiles: 'trivy-results.json'
        testRunTitle: 'Trivy Vulnerability Scan'
      condition: always()` : ''}

${tools.zap ? `    - script: |
        docker run --rm -v "\\$(pwd):/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t \\$(System.TeamFoundationCollectionUri)/\\$(System.TeamProject)/_git/\\$(Build.Repository.Name)
      displayName: 'Run OWASP ZAP DAST'
      continueOnError: true` : ''}

${notifications.email ? `    - task: EmailReport@1
      displayName: 'Send Email Notification'
      inputs:
        to: '\\$(notification.email)'
        subject: 'Security Scan Results - \\$(Build.BuildNumber)'
        body: 'Security scan completed with status: \\$(Agent.JobStatus)'
      condition: always()` : ''}

    - task: PublishBuildArtifacts@1
      displayName: 'Publish Security Reports'
      inputs:
        pathToPublish: '\\$(System.DefaultWorkingDirectory)'
        artifactName: 'security-reports'
      condition: always()
`;
}

const port = process.env.PORT || 4000;
app.listen(port, () => console.log('Backend listening on', port));
