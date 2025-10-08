
#!/usr/bin/env bash
LAB=$1
echo "Simulating semgrep run against $LAB..."
sleep 2
echo '{"findings": [{"rule":"example-rule","severity":"MEDIUM","message":"Example issue from semgrep"}]}' > ../backend/results/${LAB}_semgrep.json
echo "Semgrep simulation complete."
