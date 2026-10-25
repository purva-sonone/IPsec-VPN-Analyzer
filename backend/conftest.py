import os
import sys

# Ensure backend and backend/core are on sys.path for test runners (pytest, etc.)
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
CORE_DIR = os.path.join(BACKEND_DIR, "core")

for d in (BACKEND_DIR, CORE_DIR):
    if d not in sys.path:
        sys.path.insert(0, d)
