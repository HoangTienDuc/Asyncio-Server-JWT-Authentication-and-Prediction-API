from enum import Enum
from pathlib import Path

    
ASYMMETRIC_PUBLIC_KEY_PATH = Path("./data/public_key.pem")
ASYMMETRIC_PRIVATE_KEY_PATH = Path("./data/private_key.pem")
UPLOAD_DIR = Path("uploads")

if not UPLOAD_DIR.exists():
    UPLOAD_DIR.mkdir(exist_ok=True)
    
class Status(Enum):
    FileNotFoundError = 2
    PermissionError = 13
