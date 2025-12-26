
import os
import sys


PROJECT_ROOT = os.path.dirname(__file__)

if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

WEB_INTERFACE_DIR = os.path.join(PROJECT_ROOT, "web_interface")
if WEB_INTERFACE_DIR not in sys.path:
    sys.path.insert(0, WEB_INTERFACE_DIR)

from web_interface.app import app as application
from web_interface.database import init_database

init_database(application)
