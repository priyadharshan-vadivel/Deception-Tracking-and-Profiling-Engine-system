#!/bin/bash
# =============================================================
# setup_server1_website.sh
# Sets up the real web application on Server1 (192.168.56.103).
# Creates a convincing corporate portal that attackers will target.
# Also places honeytoken files for detection.
#
# Run on Server1:
#   sudo bash setup_server1_website.sh
# =============================================================

echo "[+] Setting up real web application on Server1..."

# Install Apache
apt-get install -y apache2 2>/dev/null
systemctl enable apache2
systemctl start apache2

# ── Real Corporate Homepage ──
cat > /var/www/html/index.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Acme Corporation - Internal Portal</title>
  <style>
    * { margin:0; padding:0; box-sizing:border-box; }
    body { font-family: Arial, sans-serif; background: #f4f4f4; color: #333; }
    header { background: #003366; color: white; padding: 20px 40px;
             display: flex; justify-content: space-between; align-items: center; }
    header h1 { font-size: 24px; }
    header span { font-size: 13px; color: #aac4e8; }
    nav { background: #0055a5; padding: 10px 40px; }
    nav a { color: white; margin-right: 25px; text-decoration: none; font-size: 14px; }
    nav a:hover { text-decoration: underline; }
    .hero { background: linear-gradient(135deg, #003366, #0055a5);
            color: white; padding: 60px 40px; text-align: center; }
    .hero h2 { font-size: 32px; margin-bottom: 15px; }
    .hero p { font-size: 16px; color: #cce0ff; margin-bottom: 25px; }
    .btn { background: #ff6600; color: white; padding: 12px 30px;
           border-radius: 4px; text-decoration: none; font-size: 15px; }
    .cards { display: flex; gap: 20px; padding: 40px; justify-content: center; }
    .card { background: white; border-radius: 8px; padding: 25px; width: 220px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1); text-align: center; }
    .card h3 { color: #003366; margin-bottom: 10px; }
    .card p { font-size: 13px; color: #666; }
    footer { background: #222; color: #888; text-align: center; padding: 15px; font-size: 13px; }
  </style>
</head>
<body>
  <header>
    <h1>🏢 Acme Corporation</h1>
    <span>Internal Employee Portal v2.4</span>
  </header>
  <nav>
    <a href="/">Home</a>
    <a href="/login.html">Employee Login</a>
    <a href="/about.html">About</a>
    <a href="/contact.html">Contact IT</a>
  </nav>
  <div class="hero">
    <h2>Welcome to the Acme Internal Portal</h2>
    <p>Access your HR records, IT resources, and company documents securely.</p>
    <a href="/login.html" class="btn">Employee Login →</a>
  </div>
  <div class="cards">
    <div class="card">
      <h3>📋 HR Portal</h3>
      <p>Access payslips, leave requests, and employee records.</p>
    </div>
    <div class="card">
      <h3>💻 IT Support</h3>
      <p>Submit tickets, reset passwords, and access tools.</p>
    </div>
    <div class="card">
      <h3>📁 Documents</h3>
      <p>Internal policies, SOPs, and company guidelines.</p>
    </div>
  </div>
  <footer>© 2024 Acme Corporation. Unauthorized access is prohibited and monitored.</footer>
</body>
</html>
HTMLEOF

# ── Real Login Page ──
cat > /var/www/html/login.html << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login - Acme Corp</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f0f2f5; }
    .container { width: 380px; margin: 80px auto; }
    .logo { text-align: center; margin-bottom: 20px; color: #003366; font-size: 22px; font-weight: bold; }
    .box { background: white; padding: 35px; border-radius: 8px;
           box-shadow: 0 2px 15px rgba(0,0,0,0.1); }
    h2 { color: #003366; margin-bottom: 20px; font-size: 20px; }
    label { display: block; margin-bottom: 5px; font-size: 13px; color: #555; }
    input { width: 100%; padding: 11px; margin-bottom: 15px;
            border: 1px solid #ccc; border-radius: 4px; font-size: 14px; }
    input:focus { border-color: #0055a5; outline: none; }
    button { width: 100%; padding: 12px; background: #003366;
             color: white; border: none; border-radius: 4px;
             font-size: 15px; cursor: pointer; }
    button:hover { background: #0055a5; }
    .footer-note { text-align: center; margin-top: 15px; font-size: 12px; color: #999; }
    .warning { background: #fff3cd; border: 1px solid #ffc107; padding: 10px;
               border-radius: 4px; font-size: 12px; color: #856404; margin-bottom: 15px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">🏢 Acme Corporation</div>
    <div class="box">
      <h2>Employee Sign In</h2>
      <div class="warning">⚠️ This system is for authorized users only. All access is logged.</div>
      <form method="POST" action="/login">
        <label>Username</label>
        <input type="text" name="username" placeholder="Enter your username" required>
        <label>Password</label>
        <input type="password" name="password" placeholder="Enter your password" required>
        <button type="submit">Sign In</button>
      </form>
      <div class="footer-note">Forgot password? Contact IT Support at ext. 1234</div>
    </div>
  </div>
</body>
</html>
HTMLEOF

# ── About Page ──
cat > /var/www/html/about.html << 'HTMLEOF'
<!DOCTYPE html>
<html><head><title>About - Acme Corp</title></head>
<body style="font-family:Arial;padding:40px;">
<h1>About Acme Corporation</h1>
<p>Acme Corporation is a leading technology company founded in 1995.</p>
<p>Headquarters: 123 Business Park, Tech City, TC 10001</p>
<p>Employees: 2,400+ worldwide</p>
</body></html>
HTMLEOF

# ── Contact Page ──
cat > /var/www/html/contact.html << 'HTMLEOF'
<!DOCTYPE html>
<html><head><title>Contact IT - Acme Corp</title></head>
<body style="font-family:Arial;padding:40px;">
<h1>IT Support</h1>
<p>Email: it-support@acme-corp.local</p>
<p>Phone: ext. 1234</p>
<p>Hours: Monday-Friday 8am-6pm</p>
</body></html>
HTMLEOF

# ── Honeytoken Files ──
echo "[+] Placing honeytoken files..."
echo "FAKE BACKUP HONEYTOKEN - ACCESS IS MONITORED AND LOGGED" > /var/www/html/secret-backup.zip
echo "-- FAKE SQL DUMP - HONEYTOKEN - ACCESS LOGGED" > /var/www/html/database-dump.sql
printf "DB_PASSWORD=HONEYTOKEN_FAKE_PASSWORD\nAPI_KEY=HONEYTOKEN_FAKE_API_KEY" > /var/www/html/.env
echo "admin:HONEYTOKEN_FAKE_PASS" > /var/www/html/passwords.txt
echo '{"admin":"HONEYTOKEN_FAKE","note":"access logged"}' > /var/www/html/admin-credentials.json

# ── Enable IP forwarding for DNAT redirection ──
echo "[+] Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || \
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p 2>/dev/null || true

systemctl restart apache2

echo ""
echo "[+] Server1 web application setup complete!"
echo "[+] Real website:  http://192.168.56.103/"
echo "[+] Login page:    http://192.168.56.103/login.html"
echo "[+] Honeytokens:   /var/www/html/{.env,passwords.txt,database-dump.sql}"
