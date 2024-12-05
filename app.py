from flask import Flask, request, jsonify, render_template, send_file, session
import requests
from flask_cors import CORS
import json
import re
import time
import os
from secret_key import MOBSF_API_KEY, MOBSF_API_URL, secret_key
app = Flask(__name__)
CORS(app)


PDF_DIR = 'pdf_reports'
os.makedirs(PDF_DIR, exist_ok=True)


@app.route('/')
def index():
    return render_template('index.html')


def extract_vulnerabilities(data):

    vulnerabilities = {
        "insecure_data_storage": [],
        "weak_permissions": [],
        "network_issues": [],
        "security_score": []

    }
    security_score = data.get("appsec", {}).get("security_score")

    def cleanseHTML(text: str) -> str:
        return re.sub(r'<.*?>', '', text)
    print(security_score)
    # Parsing data for each vulnerability category
    for finding in data.get("manifest_analysis", {}).get("manifest_findings", []):
        title = finding.get("title", "")
        description = finding.get("description", "")
        severity = finding.get("severity", "")
        # if severity == "info" or severity == "normal" or severity == "warning" or severity == "unknown":
        #     continue
        # Insecure Data Storage
        if any(keyword in title.lower() for keyword in ["record", "camera", "storage", "write", "read", "billing", "data", "backup"]):
            vulnerabilities["insecure_data_storage"].append({
                "title": cleanseHTML(title),
                "description": description,
                "severity": severity
            })

        # Improper Encryption
        elif any(keyword in title.lower() for keyword in ["internet", "network", "wifi", "socket", "adservices", "location", "access", "change"]):
            vulnerabilities["network_issues"].append({
                "title": cleanseHTML(title),
                "description": description,
                "severity": severity
            })

        # Weak Permissions
        elif any(keyword in title.lower() for keyword in ["receive_boot", "set_wallpaper", "wake_lock", "ignore_battery", "use_credentials", "get_accounts", "notification", "post", "unknown", "call", "send", "sms", "receive"]):
            vulnerabilities["weak_permissions"].append({
                "title": cleanseHTML(title),
                "description": description,
                "severity": severity
            })

    for perm, details in data.get("permissions", {}).items():
        title = perm
        description = details.get("description", "")
        severity = details.get("status", "")
        # if severity == "info" or severity == "normal" or severity == "warning" or severity == "unknown":
        #     continue
        # Check for insecure data storage-related permissions
        if any(keyword in perm.lower() for keyword in ["record", "camera", "storage", "write", "read", "billing", "data", "backup"]):
            vulnerabilities["insecure_data_storage"].append({
                "title": perm,
                "description": description,
                "severity": severity
            })
        # Check for weak permission-related permissions
        elif any(keyword in perm.lower() for keyword in ["receive_boot", "set_wallpaper", "wake_lock", "ignore_battery", "use_credentials", "get_accounts", "notification", "post", "unknown", "call", "send", "sms", "receive", "face", "biometric", "photo"]):
            vulnerabilities["weak_permissions"].append({
                "title": perm,
                "description": description,
                "severity": severity
            })
        # Check for network issue-related permissions
        elif any(keyword in perm.lower() for keyword in ["internet", "network", "wifi", "socket", "adservices", "location", "access", "change"]):
            vulnerabilities["network_issues"].append({
                "title": perm,
                "description": description,
                "severity": severity
            })
    security_score = data.get("appsec", {}).get("security_score")
    vulnerabilities["security_score"].append(security_score)
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
        print(scan_payload)
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
        time.sleep(3)
        # Render dashboard with vulnerabilities
        return render_template('dashboard.html', vulnerabilities=vulnerabilities, total_vulnerabilities=total_vulnerabilities, filename=file.filename)

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
