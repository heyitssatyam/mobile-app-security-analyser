from flask import Flask, request, jsonify, render_template, send_file, session
import requests
from flask_cors import CORS
import json
import re
import time
import os

app = Flask(__name__)
CORS(app)
MOBSF_API_URL = 'http://localhost:8000/api/v1/'
MOBSF_API_KEY = 'fb2a8d2411a2cf4dfa5e536496caab62e8070ae820637b2455a5f38178a27f82'

# Secret key for session management
# Use a secure and random key in production
app.secret_key = 'adsfoaijsdf32r893rifajsdoifjoiejfa'

# Define where the PDFs will be stored temporarily
PDF_DIR = 'pdf_reports'
os.makedirs(PDF_DIR, exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')


def extract_vulnerabilities(data):
    vulnerabilities = {
        "insecure_data_storage": [],
        "improper_encryption": [],
        "weak_permissions": [],
        "network_issues": []
    }

    def cleanseHTML(text: str) -> str:
        return re.sub(r'<.*?>', '', text)

    # Parsing data for each vulnerability category
    for finding in data.get("manifest_analysis", {}).get("manifest_findings", []):
        title = finding.get("title", "")
        description = finding.get("description", "")
        severity = finding.get("severity", "")

        # Insecure Data Storage
        if "debug" in title.lower() or "application data" in title.lower() or "data" in title.lower() or "debugger" in title.lower():
            vulnerabilities["insecure_data_storage"].append({
                "title": cleanseHTML(title),
                "description": description,
                "severity": severity
            })

        # Improper Encryption
        elif "encryption" in title.lower() or "crypto" in title.lower() or "sha1" in title.lower():
            vulnerabilities["improper_encryption"].append({
                "title": cleanseHTML(title),
                "description": description,
                "severity": severity
            })

        # Weak Permissions
        elif "permission" in title.lower() or "exported" in title.lower():
            vulnerabilities["weak_permissions"].append({
                "title": cleanseHTML(title),
                "description": description,
                "severity": severity
            })

    for perm, details in data.get("permissions", {}).items():
        # Check for insecure data storage-related permissions
        if any(keyword in perm.lower() for keyword in ["record", "camera", "storage", "write", "read", "billing", "data", "backup"]):
            vulnerabilities["insecure_data_storage"].append({
                "title": perm,
                "description": details.get("description", ""),
                "severity": details.get("status", "")
            })
        # Check for weak permission-related permissions
        elif any(keyword in perm.lower() for keyword in ["receive_boot", "set_wallpaper", "wake_lock", "ignore_battery", "use_credentials", "get_accounts", "notification", "post", "unknown", "call", "send", "sms", "receive"]):
            vulnerabilities["weak_permissions"].append({
                "title": perm,
                "description": details.get("description", ""),
                "severity": details.get("status", "")
            })
        # Check for network issue-related permissions
        elif any(keyword in perm.lower() for keyword in ["internet", "network", "wifi", "socket", "adservices", "location", "access", "change"]):
            vulnerabilities["network_issues"].append({
                "title": perm,
                "description": details.get("description", ""),
                "severity": details.get("status", "")
            })
    return vulnerabilities


@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file.filename.endswith('.apk'):
        content_type = 'application/vnd.android.package-archive'
    elif file.filename.endswith('.ipa'):
        content_type = 'application/octet-stream'
    else:
        return jsonify({'error': 'Unsupported file type'}), 400

    # Send file to MobSF for analysis
    files = {'file': (file.filename, file.stream, content_type)}
    headers = {'Authorization': MOBSF_API_KEY}

    try:
        # Upload the file to MobSF
        upload_response = requests.post(
            MOBSF_API_URL + 'upload', files=files, headers=headers)

        if upload_response.status_code != 200:
            print("Upload Error:", upload_response.text)
            return jsonify({'error': 'Failed to upload APK to MobSF'}), 500

        upload_data = upload_response.json()
        file_hash = upload_data.get('hash')

        if not file_hash:
            return jsonify({'error': 'Hash not returned from MobSF'}), 500

        # Request the scan
        scan_payload = {'hash': file_hash}
        scan_response = requests.post(
            MOBSF_API_URL + 'scan', data=scan_payload, headers=headers)

        if scan_response.status_code != 200:
            print("Scan Error:", scan_response.text)
            return jsonify({'error': 'Failed to analyze APK'}), 500

        vulnerabilities = extract_vulnerabilities(scan_response.json())

        total_vulnerabilities = sum(len(v) for v in vulnerabilities.values())
        # Store the file_hash for later PDF download
        session['file_hash'] = file_hash
        with open('data.json', 'w') as f:
            json.dump(scan_response.json(), f)
        time.sleep(4)
        # Render dashboard with vulnerabilities
        return render_template('dashboard.html', vulnerabilities=vulnerabilities, total_vulnerabilities=total_vulnerabilities)

    except Exception as e:
        print("Exception occurred:", str(e))
        return jsonify({'error': str(e)}), 500


@app.route('/download_pdf', methods=['GET'])
def download_pdf():
    # Check if file_hash is available in the session
    file_hash = session.get('file_hash')

    if not file_hash:
        return jsonify({'error': 'No scan file available for PDF download'}), 400

    headers = {'Authorization': MOBSF_API_KEY}
    scan_payload = {'hash': file_hash}

    try:
        # Fetch the PDF report from MobSF
        pdf_response = requests.post(
            MOBSF_API_URL + 'download_pdf', data=scan_payload, headers=headers)

        if pdf_response.status_code == 200:
            # Save PDF to a file
            pdf_path = os.path.join(PDF_DIR, f"{file_hash}_report.pdf")
            with open(pdf_path, 'wb') as f:
                f.write(pdf_response.content)

            # Return the PDF file as a downloadable response
            return send_file(pdf_path, as_attachment=True, mimetype='application/pdf', download_name=f"{file_hash}_report.pdf")
        else:
            print("PDF Error:", pdf_response.text)
            return jsonify({'error': 'Failed to download PDF report'}), 500

    except Exception as e:
        print("Exception occurred:", str(e))
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.secret_key = 'your_secret_key'  # Required for session management
    app.run(debug=True)
