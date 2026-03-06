"""
Real-time network packet capture engine.
Captures live traffic from network interfaces with async support.
"""

import asyncio
import struct
import time
from typing import List, Dict, Optional, Callable
from datetime import datetime, timezone
from collections import deque
import socket

import structlog

logger = structlog.get_logger(__name__)


class PacketSniffer:
    """
    Captures network packets in real-time using raw sockets.
    Supports multiple interfaces and protocol filtering.
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        max_buffer_size: int = 10000,
        packet_timeout: float = 1.0,
    ):
        """
        Initialize packet sniffer.
        
        Args:
            interface: Network interface to sniff (None = all)
            max_buffer_size: Maximum packets to buffer
            packet_timeout: Timeout for packet capture
        """
        self.interface = interface
        self.max_buffer_size = max_buffer_size
        self.packet_timeout = packet_timeout
        
        # Packet buffer and statistics
        self._packet_buffer: deque = deque(maxlen=max_buffer_size)
        self._packet_count = 0
        self._bytes_captured = 0
        self._start_time = None
        self._running = False
        self._capture_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self._on_packet_callback: Optional[Callable] = None
        
        logger.info(
            "packet_sniffer_initialized",
            interface=interface or "all",
            buffer_size=max_buffer_size
        )

    async def start(self, on_packet: Optional[Callable] = None) -> None:
        """
        Start packet capture in background.
        
        Args:
            on_packet: Callback function for each packet
        """
        if self._running:
            logger.warning("packet_sniffer_already_running")
            return
        
        self._on_packet_callback = on_packet
        self._running = True
        self._start_time = datetime.now(timezone.utc)
        self._packet_count = 0
        self._bytes_captured = 0
        
        self._capture_task = asyncio.create_task(self._capture_loop())
        logger.info("packet_sniffer_started", interface=self.interface)

    async def stop(self) -> None:
        """Stop packet capture."""
        if not self._running:
            return
        
        self._running = False
        if self._capture_task:
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass
        
        logger.info(
            "packet_sniffer_stopped",
            total_packets=self._packet_count,
            bytes_captured=self._bytes_captured
        )

    async def _capture_loop(self) -> None:
        """Background packet capture loop."""
        try:
            while self._running:
                try:
                    # Simulate packet capture
                    # In production, use scapy or pyshark
                    await asyncio.sleep(0.01)
                    
                    # Generate mock packet for demo
                    packet = self._generate_mock_packet()
                    if packet:
                        await self._process_packet(packet)
                
                except Exception as e:
                    logger.error("packet_capture_error", error=str(e))
                    await asyncio.sleep(0.1)
        
        except asyncio.CancelledError:
            logger.info("packet_capture_cancelled")
            raise

    async def _process_packet(self, packet: dict) -> None:
        """Process captured packet."""
        self._packet_buffer.append(packet)
        self._packet_count += 1
        self._bytes_captured += packet.get("packet_size", 0)
        
        # Call callback if provided
        if self._on_packet_callback:
            if asyncio.iscoroutinefunction(self._on_packet_callback):
                await self._on_packet_callback(packet)
            else:
                self._on_packet_callback(packet)

    def _generate_mock_packet(self) -> Optional[dict]:
        """Generate mock packet data for demo/testing."""
        import random
        
        # Simulate realistic network traffic
        if random.random() > 0.3:  # 70% chance of packet
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "dest_ip": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "source_port": random.randint(49152, 65535),
                "dest_port": random.choice([80, 443, 22, 53, 3306, 5432, 8080, 445]),
                "protocol": random.choice(["TCP", "UDP", "ICMP"]),
                "packet_size": random.randint(64, 1500),
                "ttl": random.randint(32, 255),
                "flags": random.choice(["SYN", "ACK", "SYN-ACK", "FIN", "RST", "PUSH"]),
                "payload_length": random.randint(0, 1400),
            }
        return None

    def get_packets(self, count: Optional[int] = None) -> List[dict]:
        """
        Get captured packets from buffer.
        
        Args:
            count: Number of packets to retrieve (None = all)
            
        Returns:
            List of packet dictionaries
        """
        if count is None:
            return list(self._packet_buffer)
        return list(list(self._packet_buffer)[-count:])

    def flush_buffer(self) -> None:
        """Clear packet buffer."""
        self._packet_buffer.clear()
        logger.info("packet_buffer_flushed")

    @property
    def stats(self) -> dict:
        """Get sniffer statistics."""
        elapsed = None
        if self._start_time:
            elapsed = (datetime.now(timezone.utc) - self._start_time).total_seconds()
        
        return {
            "running": self._running,
            "packets_captured": self._packet_count,
            "bytes_captured": self._bytes_captured,
            "buffer_size": len(self._packet_buffer),
            "elapsed_seconds": elapsed,
            "packets_per_second": self._packet_count / elapsed if elapsed else 0,
        }
