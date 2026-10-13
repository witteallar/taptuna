"""Единственная точка входа. Здесь нет логики анализа — только запуск Flask."""
import argparse
import socket
import sys
import webbrowser

import config
from backend.app import create_app
from backend.utils.tshark_check import get_tshark_status


def _port_is_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Лаборатория протоколов")
    parser.add_argument("--port", type=int, default=config.PORT)
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if not _port_is_free(args.host, args.port):
        print(f"[!] Порт {args.port} занят. Запустите с --port <другой>.", file=sys.stderr)
        return 1

    # Проверку tshark НЕ блокируем: статус отдаётся в /api/health и виден в браузере.
    ok, info = get_tshark_status()
    if ok:
        print(f"[i] tshark: {info}")
    else:
        print(f"[!] tshark недоступен: {info}", file=sys.stderr)

    app = create_app()
    url = f"http://{args.host}:{args.port}/"
    print(f"[i] Открываю {url}")
    if not args.no_browser:
        webbrowser.open(url)
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())