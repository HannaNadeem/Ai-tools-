# ==============================================================================
# File: dummy_agent.py
# Version: 1.0
# Description: A lightweight dummy agent for testing the Fleet Command server.
#              It registers itself and sends fake metrics periodically without
#              running a full web server.
# ==============================================================================
import httpx
import time
import random
import os
import platform
import logging

# --- Dummy Agent Configuration ---
# This agent reads its configuration from environment variables,
# just like a real agent.
class DummyAgentSettings:
    def __init__(self, hostname_suffix=""):
        self.HOSTNAME = os.getenv("AGENT_HOSTNAME", f"{platform.node()}{hostname_suffix}")
        self.IP_ADDRESS = os.getenv("AGENT_IP_ADDRESS", "127.0.0.1")
        self.PORT = int(os.getenv("AGENT_PORT", 8001))
        self.GROUP = os.getenv("AGENT_GROUP", "dummy-servers")
        self.MAIN_SERVER_URL = os.getenv("MAIN_SERVER_URL", "http://127.0.0.1:8000")
        self.MASTER_REGISTRATION_KEY = os.getenv("MASTER_REGISTRATION_KEY", "NOT_SET")
        self.HEARTBEAT_INTERVAL = int(os.getenv("HEARTBEAT_INTERVAL", 10)) # Faster updates for testing
        self.AGENT_API_KEY = None # Will be fetched from the server

settings = DummyAgentSettings()
logging.basicConfig(level=logging.INFO, format=f'%(asctime)s - DUMMY AGENT ({settings.HOSTNAME}) - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def generate_fake_metrics():
    """Generates random but realistic-looking server metrics."""
    return {
        "cpu_usage": round(random.uniform(5.0, 50.0), 2),
        "memory_usage": round(random.uniform(30.0, 75.0), 2),
        "disk_usage": round(random.uniform(20.0, 80.0), 2),
        "uptime": f"{random.randint(1, 30)} days, {random.randint(0, 23)}:mm:ss"
    }

def run_dummy_agent():
    """Main function to run the dummy agent's lifecycle."""
    # 1. Register with the main server
    logger.info(f"Attempting to register with the main server at {settings.MAIN_SERVER_URL}...")
    register_payload = {
        "hostname": settings.HOSTNAME, "ip_address": settings.IP_ADDRESS,
        "port": settings.PORT, "os_info": f"Dummy OS ({platform.system()})", "group": settings.GROUP
    }
    headers = {"X-Master-Key": settings.MASTER_REGISTRATION_KEY}
    try:
        with httpx.Client() as client:
            response = client.post(f"{settings.MAIN_SERVER_URL}/agent/register", json=register_payload, headers=headers, timeout=20)
            response.raise_for_status()
            data = response.json()
            settings.AGENT_API_KEY = data["api_key"]
            logger.info("Registration successful. Received unique API key.")
    except Exception as e:
        logger.critical(f"CRITICAL: Agent registration failed: {e}. The dummy agent cannot start.")
        return

    # 2. Start sending periodic heartbeats
    logger.info("Starting heartbeat loop...")
    while True:
        try:
            metrics = generate_fake_metrics()
            headers = {"X-API-Key": settings.AGENT_API_KEY}
            with httpx.Client() as client:
                response = client.post(f"{settings.MAIN_SERVER_URL}/agent/heartbeat/{settings.HOSTNAME}", json=metrics, headers=headers, timeout=10)
                if response.status_code == 200:
                    logger.info(f"Heartbeat sent: CPU {metrics['cpu_usage']}% | Memory {metrics['memory_usage']}%")
                else:
                    logger.warning(f"Heartbeat failed. Status: {response.status_code}, Response: {response.text}")
        except Exception as e:
            logger.error(f"Error in heartbeat loop: {e}")
        
        time.sleep(settings.HEARTBEAT_INTERVAL)

if __name__ == "__main__":
    # Allows running multiple dummy agents by passing a suffix, e.g., python dummy_agent.py -dummy-2
    import sys
    suffix = sys.argv[1] if len(sys.argv) > 1 else ""
    settings = DummyAgentSettings(hostname_suffix=suffix)
    run_dummy_agent()
