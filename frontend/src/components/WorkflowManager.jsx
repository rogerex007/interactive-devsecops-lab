import React, { useState } from 'react';

const WorkflowManager = ({ isOpen, onClose }) => {
  const [selectedPlatform, setSelectedPlatform] = useState('github');
  const [workflowConfig, setWorkflowConfig] = useState({
    name: 'security-scan',
    trigger: 'push',
    branches: ['main', 'develop'],
    tools: {
      semgrep: true,
      trivy: true,
      zap: false
    },
    schedule: '0 2 * * *', // Daily at 2 AM
    notifications: {
      slack: false,
      email: true,
      github: true
    }
  });

  const generateGitHubWorkflow = () => {
    const { name, trigger, branches, tools, schedule, notifications } = workflowConfig;
    
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
  };

  const generateAzureDevOpsPipeline = () => {
    const { name, trigger, branches, tools, schedule, notifications } = workflowConfig;
    
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
  };

  const handleConfigChange = (key, value) => {
    setWorkflowConfig(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleToolToggle = (tool) => {
    setWorkflowConfig(prev => ({
      ...prev,
      tools: {
        ...prev.tools,
        [tool]: !prev.tools[tool]
      }
    }));
  };

  const handleNotificationToggle = (notification) => {
    setWorkflowConfig(prev => ({
      ...prev,
      notifications: {
        ...prev.notifications,
        [notification]: !prev.notifications[notification]
      }
    }));
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    // You could add a toast notification here
  };

  if (!isOpen) return null;

  const workflowContent = selectedPlatform === 'github' ? generateGitHubWorkflow() : generateAzureDevOpsPipeline();

  return (
    <div style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    }}>
      <div style={{
        backgroundColor: 'white',
        borderRadius: '15px',
        width: '90%',
        maxWidth: '1200px',
        maxHeight: '90vh',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          color: 'white',
          padding: '20px 30px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center'
        }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '1.8rem', fontWeight: '700' }}>
              🚀 Workflow Manager
            </h2>
            <p style={{ margin: '4px 0 0 0', opacity: 0.9 }}>
              Genera pipelines de CI/CD para automatizar escaneos de seguridad
            </p>
          </div>
          <button 
            onClick={onClose}
            style={{
              background: 'rgba(255, 255, 255, 0.2)',
              border: 'none',
              color: 'white',
              padding: '10px 15px',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '1rem',
              fontWeight: '600'
            }}
          >
            ✕ Cerrar
          </button>
        </div>

        {/* Content */}
        <div style={{
          display: 'flex',
          height: 'calc(90vh - 100px)',
          overflow: 'hidden'
        }}>
          {/* Configuration Panel */}
          <div style={{
            width: '350px',
            padding: '30px',
            borderRight: '1px solid #e2e8f0',
            overflowY: 'auto',
            backgroundColor: '#f8fafc'
          }}>
            <h3 style={{ margin: '0 0 20px 0', color: '#1f2937', fontSize: '1.3rem' }}>
              ⚙️ Configuración
            </h3>

            {/* Platform Selection */}
            <div style={{ marginBottom: 25 }}>
              <label style={{ display: 'block', marginBottom: 8, fontWeight: '600', color: '#374151' }}>
                Plataforma
              </label>
              <div style={{ display: 'flex', gap: 10 }}>
                <button
                  onClick={() => setSelectedPlatform('github')}
                  style={{
                    flex: 1,
                    padding: '12px',
                    border: selectedPlatform === 'github' ? '2px solid #3b82f6' : '2px solid #d1d5db',
                    borderRadius: '8px',
                    background: selectedPlatform === 'github' ? '#eff6ff' : 'white',
                    cursor: 'pointer',
                    fontWeight: '600'
                  }}
                >
                  GitHub Actions
                </button>
                <button
                  onClick={() => setSelectedPlatform('azure')}
                  style={{
                    flex: 1,
                    padding: '12px',
                    border: selectedPlatform === 'azure' ? '2px solid #0078d4' : '2px solid #d1d5db',
                    borderRadius: '8px',
                    background: selectedPlatform === 'azure' ? '#e6f7ff' : 'white',
                    cursor: 'pointer',
                    fontWeight: '600'
                  }}
                >
                  Azure DevOps
                </button>
              </div>
            </div>

            {/* Basic Config */}
            <div style={{ marginBottom: 25 }}>
              <label style={{ display: 'block', marginBottom: 8, fontWeight: '600', color: '#374151' }}>
                Nombre del Workflow
              </label>
              <input
                type="text"
                value={workflowConfig.name}
                onChange={(e) => handleConfigChange('name', e.target.value)}
                style={{
                  width: '100%',
                  padding: '12px',
                  border: '1px solid #d1d5db',
                  borderRadius: '8px',
                  fontSize: '1rem'
                }}
              />
            </div>

            <div style={{ marginBottom: 25 }}>
              <label style={{ display: 'block', marginBottom: 8, fontWeight: '600', color: '#374151' }}>
                Trigger
              </label>
              <select
                value={workflowConfig.trigger}
                onChange={(e) => handleConfigChange('trigger', e.target.value)}
                style={{
                  width: '100%',
                  padding: '12px',
                  border: '1px solid #d1d5db',
                  borderRadius: '8px',
                  fontSize: '1rem'
                }}
              >
                <option value="push">Push</option>
                <option value="pull_request">Pull Request</option>
                <option value="both">Push & PR</option>
              </select>
            </div>

            {/* Tools Selection */}
            <div style={{ marginBottom: 25 }}>
              <label style={{ display: 'block', marginBottom: 12, fontWeight: '600', color: '#374151' }}>
                Herramientas de Seguridad
              </label>
              {Object.entries(workflowConfig.tools).map(([tool, enabled]) => (
                <label key={tool} style={{
                  display: 'flex',
                  alignItems: 'center',
                  marginBottom: 10,
                  cursor: 'pointer'
                }}>
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={() => handleToolToggle(tool)}
                    style={{ marginRight: 10 }}
                  />
                  <span style={{ fontWeight: '500' }}>
                    {tool === 'semgrep' ? '🔍 Semgrep (SAST)' :
                     tool === 'trivy' ? '📦 Trivy (SCA)' :
                     '🌐 OWASP ZAP (DAST)'}
                  </span>
                </label>
              ))}
            </div>

            {/* Notifications */}
            <div style={{ marginBottom: 25 }}>
              <label style={{ display: 'block', marginBottom: 12, fontWeight: '600', color: '#374151' }}>
                Notificaciones
              </label>
              {Object.entries(workflowConfig.notifications).map(([notification, enabled]) => (
                <label key={notification} style={{
                  display: 'flex',
                  alignItems: 'center',
                  marginBottom: 10,
                  cursor: 'pointer'
                }}>
                  <input
                    type="checkbox"
                    checked={enabled}
                    onChange={() => handleNotificationToggle(notification)}
                    style={{ marginRight: 10 }}
                  />
                  <span style={{ fontWeight: '500' }}>
                    {notification === 'slack' ? '💬 Slack' :
                     notification === 'email' ? '📧 Email' :
                     '🔔 GitHub'}
                  </span>
                </label>
              ))}
            </div>
          </div>

          {/* Code Preview Panel */}
          <div style={{
            flex: 1,
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            <div style={{
              padding: '20px 30px',
              borderBottom: '1px solid #e2e8f0',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              backgroundColor: '#f8fafc'
            }}>
              <h3 style={{ margin: 0, color: '#1f2937', fontSize: '1.3rem' }}>
                📄 {selectedPlatform === 'github' ? 'GitHub Actions Workflow' : 'Azure DevOps Pipeline'}
              </h3>
              <button
                onClick={() => copyToClipboard(workflowContent)}
                style={{
                  background: '#3b82f6',
                  color: 'white',
                  border: 'none',
                  padding: '10px 20px',
                  borderRadius: '8px',
                  cursor: 'pointer',
                  fontWeight: '600',
                  fontSize: '0.9rem'
                }}
              >
                📋 Copiar
              </button>
            </div>
            
            <div style={{
              flex: 1,
              padding: '20px',
              overflow: 'auto',
              backgroundColor: '#1e293b'
            }}>
              <pre style={{
                color: '#e2e8f0',
                fontSize: '0.9rem',
                lineHeight: '1.5',
                margin: 0,
                fontFamily: 'Monaco, Menlo, "Ubuntu Mono", monospace'
              }}>
                <code>{workflowContent}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default WorkflowManager;
