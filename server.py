# server.py
from flask import Flask, request, jsonify
import json
import logging
from datetime import datetime
import time

app = Flask(__name__)

# Configure better logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_data.log"),
        logging.StreamHandler()
    ]
)

# Track received sequences to detect missing data
sequence_tracker = {}

@app.route('/data', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "No data received or invalid JSON"}), 400

        # Extract metadata
        timestamp = data.get('timestamp', time.time())
        source = data.get('source_script', 'Unknown Source')
        batch_id = data.get('batch_id', 'unknown_batch')
        sequence = data.get('sequence', -1)
        metrics = data.get('metrics', [])

        # Check for missing sequences
        if source in sequence_tracker:
            last_seq = sequence_tracker[source]
            if sequence > last_seq + 1:
                logging.warning(f"Potential missing data! Expected sequence {last_seq + 1} but received {sequence} from {source}")
        sequence_tracker[source] = sequence

        # Log the basic info about the received data
        logging.info(f"Received batch {batch_id} (seq: {sequence}) from '{source}' with {len(metrics)} metrics")
        
        # Log individual metrics
        for metric in metrics:
            logging.info(f"{metric['data']}")

        return jsonify({
            "status": "success", 
            "message": f"Received {len(metrics)} metrics",
            "batch_id": batch_id,
            "sequence_received": sequence
        }), 200

    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    print("Starting enhanced Flask server on http://0.0.0.0:5000")
    # Use 0.0.0.0 to make it accessible from other machines on the network if needed
    app.run(host='0.0.0.0', port=5000, debug=False) # Set debug=False for production/stable use