from dotenv import load_dotenv
import os

load_dotenv()

VT_API_KEY    = os.getenv("VT_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
REQUEST_TIMEOUT = 10