from flask import Flask, request, jsonify, render_template
import requests
from flask_cors import CORS
import json
import re

app = Flask(__name__)
CORS(app)
MOBSF_API_URL = 'http://localhost:8000/api/v1/'
MOBSF_API_KEY = 'fb2a8d2411a2cf4dfa5e536496caab62e8070ae820637b2455a5f38178a27f82'


@app.route('/')
def index():
    return render_template('index.html')


def extract_vulnerabilities(data):
    vulnerabilities = {
        "insecure_data_storage": [],
        "improper_encryption": [],
        "weak_permissions": []
    }

    def cleanseHTML(text: str) -> str:
        return re.sub(r'<.*?>', '', text)

        # Parsing data for each vulnerability category
    for finding in data.get("manifest_analysis", {}).get("manifest_findings", []):
        title = finding.get("title", "")
        description = finding.get("description", "")
        severity = finding.get("severity", "")

        # Insecure Data Storage
        if "storage" in title.lower() or "temp file" in title.lower():
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

    # print(vulnerabilities)
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
        # MobSF accepts IPA files as binary streams
        content_type = 'application/octet-stream'
    else:
        return jsonify({'error': 'Unsupported file type'}), 400
    # Send file to MobSF for analysis
    files = {'file': (file.filename, file.stream,
                      content_type)}
    headers = {'Authorization': MOBSF_API_KEY}

    try:
        # Upload the file to MobSF
        upload_response = requests.post(
            MOBSF_API_URL + 'upload', files=files, headers=headers)

        if upload_response.status_code != 200:
            print("Upload Error:", upload_response.text)
            return jsonify({'error': 'Failed to upload APK to MobSF'}), 500

        upload_data = upload_response.json()
        print(upload_data)
        file_hash = upload_data.get('hash')

        if not file_hash:
            return jsonify({'error': 'Hash not returned from MobSF'}), 500

        scan_payload = {'hash': file_hash}
        scan_response = requests.post(
            MOBSF_API_URL + 'scan', data=scan_payload, headers=headers)

        if scan_response.status_code != 200:
            print("Scan Error:", scan_response.text)
            return jsonify({'error': 'Failed to analyze APK'}), 500
        print("Resp", scan_response.text[:1000], scan_response.json())
        vulnerabilities = extract_vulnerabilities(
            scan_response.json())
        with open('data.json', 'w') as f:
            json.dump(scan_response.json(), f)
        return render_template('dashboard.html', vulnerabilities=vulnerabilities)

    except Exception as e:
        print("Exception occurred:", str(e))
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
