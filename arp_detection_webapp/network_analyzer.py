import os
import subprocess
import pyshark
import logging
import asyncio

logging.basicConfig(level=logging.DEBUG)
CAPTURE_FILE = 'static/captures/network_traffic.pcap'

def start_capture(interface='Wi-Fi'):
    try:
        if not os.path.exists('static/captures'):
            os.makedirs('static/captures')
        logging.debug("Starting capture with tshark")
        subprocess.Popen(['tshark', '-i', interface, '-w', CAPTURE_FILE], shell=True)
    except Exception as e:
        logging.error(f"Error starting capture: {e}")

def stop_capture():
    try:
        logging.debug("Stopping tshark capture")
        subprocess.call(['taskkill', '/IM', 'tshark.exe', '/F'], shell=True)
    except Exception as e:
        logging.error(f"Error stopping capture: {e}")

def analyze_capture():
    packet_info = []
    try:
        if not os.path.isfile(CAPTURE_FILE):
            logging.error("Capture file does not exist.")
            return {"error": "Capture file does not exist."}

        asyncio.set_event_loop(asyncio.new_event_loop())
        loop = asyncio.get_event_loop()

        capture = pyshark.FileCapture(CAPTURE_FILE, keep_packets=False)

        for packet in capture:
            try:
                packet_summary = {
                    'no': packet.number,
                    'time': str(packet.sniff_time),
                    'source': getattr(packet.ip, 'src', 'N/A'),
                    'destination': getattr(packet.ip, 'dst', 'N/A'),
                    'protocol': packet.highest_layer,
                    'length': packet.length
                }
                packet_info.append(packet_summary)
            except AttributeError as e:
                logging.error(f"Error processing packet: {e}")

    except Exception as e:
        logging.error(f"An error occurred during capture analysis: {e}")
        return {"error": f"An error occurred: {e}"}

    return {"packet_info": packet_info}
