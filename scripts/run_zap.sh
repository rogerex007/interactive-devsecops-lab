
#!/usr/bin/env bash
LAB=$1
echo "Simulating OWASP ZAP run against $LAB..."
sleep 2
echo '{"alerts": [{"name":"XSS","risk":"High","description":"Reflected XSS example"}]}' > ../backend/results/${LAB}_zap.json
echo "ZAP simulation complete."
