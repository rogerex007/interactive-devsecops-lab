
const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

const RESULTS_DIR = path.join(__dirname, 'results');
if (!fs.existsSync(RESULTS_DIR)) fs.mkdirSync(RESULTS_DIR);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', services: ['postgres','minio','juice-shop','scanners'] });
});

app.get('/labs', (req, res) => {
  res.json([{ id: 'juice-shop', name: 'OWASP Juice Shop' }]);
});

// Run a scanner job: semgrep, trivy, zap
app.post('/labs/:id/run', (req, res) => {
  const labId = req.params.id;
  const job = req.body.job; // e.g., "semgrep", "trivy", "zap"
  const outFile = path.join(RESULTS_DIR, `${labId}_${job}.json`);
  const logsFile = path.join(RESULTS_DIR, `${labId}_${job}.log`);
  let cmd = '';

  if (job === 'semgrep') {
    cmd = `bash ../scripts/run_semgrep.sh ${labId} > ${logsFile} 2>&1; echo '{ "result": "semgrep_done" }' > ${outFile}`;
  } else if (job === 'trivy') {
    cmd = `bash ../scripts/run_trivy.sh ${labId} > ${logsFile} 2>&1; echo '{ "result": "trivy_done" }' > ${outFile}`;
  } else if (job === 'zap') {
    cmd = `bash ../scripts/run_zap.sh ${labId} > ${logsFile} 2>&1; echo '{ "result": "zap_done" }' > ${outFile}`;
  } else {
    return res.status(400).json({ error: 'Unknown job' });
  }

  exec(cmd, { cwd: __dirname }, (error, stdout, stderr) => {
    // background exec
  });

  return res.json({ status: 'started', job, out: outFile, logs: logsFile });
});

app.get('/results/:file', (req, res) => {
  const file = req.params.file;
  const p = path.join(RESULTS_DIR, file);
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'file not found' });
  res.sendFile(p);
});

const port = process.env.PORT || 4000;
app.listen(port, () => console.log('Backend listening on', port));
