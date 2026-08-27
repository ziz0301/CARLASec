# attack_server.py
from flask import Flask, request, jsonify
import threading
from attacker.attack_manager import attack_mgr

def create_app():
    app = Flask(__name__)

    @app.route('/start', methods=['POST'])
    def start():
        data = request.get_json(force=True)
        attack_id = data.get('attack_id', 'A?')
        attack_type = data.get('attack_type', 'unknown')
        duration = data.get('duration', 5)
        try:
            attack_mgr.start_attack(attack_id, attack_type, duration)
            return jsonify({"status":"started", "attack_id": attack_id, "attack_type": attack_type}), 200
        except Exception as e:
            return jsonify({"status":"error", "detail": str(e)}), 500

    @app.route('/stop', methods=['POST'])
    def stop():
        attack_mgr.stop_attack()
        return jsonify({"status":"stopped"}), 200

    @app.route('/status', methods=['GET'])
    def status():
        cur = attack_mgr.get_current_attack()
        return jsonify({"current": cur}), 200

    return app

def start_attack_server(host='127.0.0.1', port=5001):
    app = create_app()
    # Run Flask in a daemon thread so it won't block your main program
    server_thread = threading.Thread(target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False), daemon=True)
    server_thread.start()
    return server_thread
