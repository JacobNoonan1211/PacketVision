import os
from flask import Flask, jsonify, render_template
import monitor

app = Flask(__name__)

_stop_event = None  # set in main()


@app.get("/api/stats")
def api_stats():
    return jsonify(monitor.get_stats())


@app.get("/")
def index():
    return render_template("index.html")


def main():
    global _stop_event
    _stop_event = __import__("threading").Event()

    # Start background monitoring
    monitor.start_monitor_thread(_stop_event)

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"

    try:
        app.run(host=host, port=port, debug=debug)
    finally:
        _stop_event.set()


if __name__ == "__main__":
    main()
