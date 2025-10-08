
#!/usr/bin/env bash
LAB=$1
echo "Simulating trivy run against $LAB..."
sleep 2
echo '{"vulnerabilities": [{"pkg":"openssl","severity":"HIGH","cvss":7.5}]}' > ../backend/results/${LAB}_trivy.json
echo "Trivy simulation complete."
