import os
import socket
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# Simulated Directory Listing files
FILES_IN_DIRECTORY = [
    "backup_config.json.bak",
    "notes.txt",
    "todo.md"
]

@app.route('/')
def index():
    # Intentionally missing X-Frame-Options and Content-Security-Policy headers
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Test Target</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #f4f6f9; color: #333; padding: 40px; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h1 { color: #d9534f; }
            a { color: #0275d8; text-decoration: none; }
            a:hover { text-decoration: underline; }
            ul { line-height: 1.8; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Authorized Vulnerable Test Target</h1>
            <p>This is a deliberately vulnerable web application for security testing and scanner validation.</p>
            <h3>Endpoints:</h3>
            <ul>
                <li><a href="/status">/status</a> - System Status Information (Private IP disclosure vulnerability)</li>
                <li><a href="/uploads/">/uploads/</a> - Uploads Directory (Directory browsing vulnerability)</li>
            </ul>
        </div>
    </body>
    </html>
    """
    return html_content

@app.route('/status')
def status():
    # Intentionally leak private IP address information
    hostname = socket.gethostname()
    try:
        private_ip = socket.gethostbyname(hostname)
    except Exception:
        private_ip = "192.168.1.100"  # Fallback typical local IP
        
    return jsonify({
        "status": "online",
        "service": "CTS-Validation-Agent",
        "internal_ip": private_ip,
        "message": f"Server status checks are running on node {hostname} with private address {private_ip}."
    })

@app.route('/uploads/')
@app.route('/uploads')
def uploads():
    # Directory Browsing / Listing vulnerability
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Index of /uploads/</title>
    </head>
    <body>
        <h1>Index of /uploads/</h1>
        <ul>
            <li><a href="/">Parent Directory</a></li>
            {% for file in files %}
                <li><a href="/uploads/{{ file }}">{{ file }}</a></li>
            {% endfor %}
        </ul>
    </body>
    </html>
    """
    return render_template_string(html_content, files=FILES_IN_DIRECTORY)

@app.route('/uploads/<filename>')
def get_file(filename):
    if filename in FILES_IN_DIRECTORY:
        return f"Contents of {filename}: Dummy confidential data for security testing.", 200
    return "File not found", 404

if __name__ == '__main__':
    # Run target app locally
    app.run(host='127.0.0.1', port=5000, debug=True)
