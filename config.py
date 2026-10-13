import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
CAPTURES_DIR = os.path.join(DATA_DIR, "captures")
PROJECTS_DIR = os.path.join(DATA_DIR, "projects")

HOST = "127.0.0.1"
PORT = 5000

MAX_FILE_SIZE = 100 * 1024 * 1024   # 100 MB
MAX_PACKETS = 250_000
TSHARK_TIMEOUT = 60
PROJECT_VERSION = "1.0"

os.makedirs(CAPTURES_DIR, exist_ok=True)
os.makedirs(PROJECTS_DIR, exist_ok=True)