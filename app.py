"""
app.py — Flask web application for BinIdentifier.

Upload an ELF binary and receive a structured vulnerability analysis
with security mitigations, detected exploit techniques, and recommendations.
"""

from __future__ import annotations

import io
import os
import tempfile

from flask import Flask, render_template, request, jsonify

from bin_identifier.analyzer import analyze_binary

app = Flask(__name__,
            static_folder="static",
            template_folder="templates")

app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB upload limit


@app.route("/")
def index():
    """Serve the main UI."""
    return render_template("index.html")


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """
    Accept a binary file upload and return JSON analysis results.

    Expects multipart/form-data with a field named ``binary``.
    """
    if "binary" not in request.files:
        return jsonify({"error": "No file uploaded. Send a file as 'binary'."}), 400

    uploaded = request.files["binary"]
    if uploaded.filename == "":
        return jsonify({"error": "Empty filename."}), 400

    # Save to temp file for dynamic auto-detection probes
    data = uploaded.read()
    stream = io.BytesIO(data)
    tmp = None

    try:
        tmp = tempfile.NamedTemporaryFile(
            prefix="binid_", suffix="_" + (uploaded.filename or "bin"),
            delete=False
        )
        tmp.write(data)
        tmp.close()
        os.chmod(tmp.name, 0o755)

        result = analyze_binary(stream, uploaded.filename, binary_path=tmp.name)
        return jsonify(result.to_dict())
    finally:
        if tmp:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
