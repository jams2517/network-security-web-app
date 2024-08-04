from flask import Flask, render_template, request, send_file, jsonify
import subprocess
import arp_spoofing_detector
import network_analyzer
import os
import logging
import threading

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

arp_detection_thread = None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_arp_detection', methods=['POST'])
def start_arp_detection():
    global arp_detection_thread
    if arp_detection_thread is None or not arp_detection_thread.is_alive():
        arp_detection_thread = threading.Thread(target=arp_spoofing_detector.start_detection, args=('Wi-Fi',))
        arp_detection_thread.start()
        return jsonify({'status': 'ARP detection started'})
    else:
        return jsonify({'status': 'ARP detection is already running'})

@app.route('/start_capture', methods=['POST'])
def start_capture():
    try:
        network_analyzer.start_capture(interface='Wi-Fi')
        return jsonify({'status': 'Capture started'})
    except Exception as e:
        logging.error(f"Error starting capture: {e}")
        return jsonify({'error': str(e)})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    try:
        network_analyzer.stop_capture()
        return jsonify({'status': 'Capture stopped'})
    except Exception as e:
        logging.error(f"Error stopping capture: {e}")
        return jsonify({'error': str(e)})

@app.route('/analyze_capture', methods=['GET'])
def analyze_capture():
    try:
        result = network_analyzer.analyze_capture()
        if 'error' in result:
            logging.error(f"Error analyzing capture: {result['error']}")
        return jsonify(result)
    except Exception as e:
        logging.error(f"Error analyzing capture: {e}")
        return jsonify({'error': str(e)})

@app.route('/download_capture', methods=['GET'])
def download_capture():
    try:
        return send_file('static/captures/network_traffic.pcap', as_attachment=True)
    except Exception as e:
        logging.error(f"Error downloading capture: {e}")
        return jsonify({'error': str(e)})

@app.route('/download_logs', methods=['GET'])
def download_logs():
    try:
        return send_file('arp_spoofing_alerts.log', as_attachment=True)
    except Exception as e:
        logging.error(f"Error downloading logs: {e}")
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True)
