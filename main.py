"""
PRISM -- Privilege Risk IAM Security Mapper
Single entry point. Launches the Flask-SocketIO dashboard.
"""

import sys
import webbrowser
import threading

from loguru import logger


def main() -> None:
    """Launch the PRISM dashboard."""
    logger.remove()
    logger.add(
        sys.stderr,
        level="INFO",
        format="<green>{time:HH:mm:ss}</green> | <level>{level:<8}</level> | {message}",
    )

    logger.info("Starting PRISM -- Privilege Risk IAM Security Mapper")

    from src.dashboard.app import create_app, socketio

    app = create_app()

    def open_browser() -> None:
        webbrowser.open("http://127.0.0.1:5000")

    threading.Timer(1.5, open_browser).start()

    logger.info("Dashboard available at http://127.0.0.1:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)


if __name__ == "__main__":
    main()
