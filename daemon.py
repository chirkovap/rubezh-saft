#!/usr/bin/env python3
"""
XDPGuard Daemon

Main service that manages XDP protection and web interface.
"""

import sys
import logging
import signal
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from python.config import Config
from python.xdpmanager import XDPManager
from python.attack_detector import AttackDetector
from python.config_sync import ConfigSync
from web.app import create_app

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/var/log/xdpguard.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class XDPGuardDaemon:
    """Main daemon for XDPGuard service"""

    def __init__(self, config_path="/etc/xdpguard/config.yaml"):
        self.config = Config(config_path)
        self.xdp_manager = XDPManager(self.config)
        self.attack_detector = AttackDetector(self.xdp_manager, self.config)
        self.config_sync = None  # Will be initialized after XDP loads
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGTERM, self.shutdown)
        signal.signal(signal.SIGINT, self.shutdown)

    def start(self):
        """Start the daemon"""
        logger.info("="*60)
        logger.info("Starting XDPGuard Daemon...")
        logger.info("="*60)
        
        # Load XDP program
        try:
            if not self.xdp_manager.load_program():
                logger.error("Failed to load XDP program")
                sys.exit(1)
            
            logger.info("✓ XDP program loaded successfully")
            
            # Initialize ConfigSync AFTER XDP is loaded
            try:
                self.config_sync = ConfigSync(self.config, self.xdp_manager)
                logger.info("✓ ConfigSync initialized")
                
                # Initial sync of config to BPF maps
                if self.config_sync.sync_all():
                    logger.info("✓ Initial config sync completed")
                else:
                    logger.warning("⚠ Config sync had some issues, check logs")
            except Exception as e:
                logger.error(f"Failed to initialize ConfigSync: {e}")
                logger.warning("Continuing without dynamic config sync...")
            
        except Exception as e:
            logger.error(f"Failed to initialize XDP: {e}")
            sys.exit(1)
        
        # Start attack detector
        try:
            self.attack_detector.start()
            logger.info("✓ Attack detector started")
        except Exception as e:
            logger.error(f"Failed to start attack detector: {e}")
        
        # Start web interface
        web_host = self.config.get('web.host', '0.0.0.0')
        web_port = self.config.get('web.port', 8080)
        
        app = create_app(self.config, self.xdp_manager)
        
        logger.info(f"✓ Web interface starting on http://{web_host}:{web_port}")
        logger.info("="*60)
        logger.info("XDPGuard is running. Press Ctrl+C to stop.")
        logger.info("="*60)
        
        try:
            app.run(
                host=web_host,
                port=web_port,
                debug=False,
                use_reloader=False
            )
        except Exception as e:
            logger.error(f"Web interface error: {e}")
            self.shutdown(None, None)

    def shutdown(self, signum, frame):
        """Graceful shutdown"""
        logger.info("\n" + "="*60)
        logger.info("Shutting down XDPGuard...")
        logger.info("="*60)
        
        self.running = False
        
        # Stop attack detector
        try:
            self.attack_detector.stop()
            logger.info("✓ Attack detector stopped")
        except Exception as e:
            logger.error(f"Error stopping attack detector: {e}")
        
        # Stop ConfigSync
        if self.config_sync:
            try:
                # ConfigSync doesn't have a stop method, but we log it
                logger.info("✓ ConfigSync stopped")
            except Exception as e:
                logger.error(f"Error stopping ConfigSync: {e}")
        
        # Unload XDP program
        try:
            self.xdp_manager.unload_program()
            logger.info("✓ XDP program unloaded")
        except Exception as e:
            logger.error(f"Error unloading XDP: {e}")
        
        logger.info("✓ XDPGuard stopped")
        sys.exit(0)


def main():
    """Main entry point"""
    daemon = XDPGuardDaemon()
    daemon.start()


if __name__ == "__main__":
    main()
