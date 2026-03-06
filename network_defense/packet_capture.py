"""
Module 1: Packet Capture Engine
Real-time network traffic capture using Scapy.
"""

import asyncio
from collections import deque
from datetime import datetime
from typing import Optional, List, Dict, Callable
import structlog
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP, Raw, Ether
from scapy.layers.http import HTTP, HTTPRequest
import threading

logger = structlog.get_logger(__name__)


class PacketCaptureEngine:
    """
    Real-time packet capture engine supporting multiple protocols.
    Captures: TCP, UDP, ICMP, DNS, HTTP, ARP
    """

    def __init__(
        self,
        interface: Optional[str] = None,
        buffer_size: int = 10000,
        packet_callback: Optional[Callable] = None
    ):
        """
        Initialize packet capture engine.
        
        Args:
            interface: Network interface to capture from (None = all interfaces)
            buffer_size: Maximum packets in buffer before processing
            packet_callback: Async callback function for captured packets
        """
        self.interface = interface
        self.buffer_size = buffer_size
        self.packet_callback = packet_callback
        
        # Packet buffer queue (thread-safe)
        self.packet_buffer: deque = deque(maxlen=buffer_size)
        self._buffer_lock = threading.Lock()
        
        # Capture state
        self._capture_active = False
        self._capture_thread: Optional[threading.Thread] = None
        
        # Statistics
        self.stats = {
            "total_packets": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "icmp_packets": 0,
            "dns_packets": 0,
            "http_packets": 0,
            "arp_packets": 0,
            "dropped_packets": 0
        }
        
        logger.info(
            "packet_capture_initialized",
            interface=interface or "all",
            buffer_size=buffer_size
        )

    def start_capture(self, filter_exp: Optional[str] = None) -> None:
        """
        Start packet capture in background thread.
        
        Args:
            filter_exp: BPF filter expression (e.g., "tcp port 80")
        """
        if self._capture_active:
            logger.warning("capture_already_running")
            return
        
        self._capture_active = True
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            args=(filter_exp,),
            daemon=True
        )
        self._capture_thread.start()
        
        logger.info(
            "packet_capture_started",
            interface=self.interface or "all",
            filter=filter_exp or "none"
        )

    def stop_capture(self) -> None:
        """Stop packet capture."""
        self._capture_active = False
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
        logger.info("packet_capture_stopped", stats=self.stats)

    def _capture_loop(self, filter_exp: Optional[str]) -> None:
        """Background capture loop using Scapy."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter=filter_exp,
                store=False,
                stop_filter=lambda p: not self._capture_active
            )
        except Exception as e:
            logger.error("capture_loop_failed", error=str(e))
            self._capture_active = False

    def _process_packet(self, packet) -> None:
        """Process individual captured packet."""
        try:
            parsed = self._parse_packet(packet)
            if parsed:
                # Add to buffer
                with self._buffer_lock:
                    if len(self.packet_buffer) >= self.buffer_size:
                        self.stats["dropped_packets"] += 1
                    else:
                        self.packet_buffer.append(parsed)
                
                # Update statistics
                self.stats["total_packets"] += 1
                protocol = parsed.get("protocol", "unknown")
                stat_key = f"{protocol.lower()}_packets"
                if stat_key in self.stats:
                    self.stats[stat_key] += 1
                
                # Invoke callback if provided
                if self.packet_callback:
                    asyncio.create_task(self.packet_callback(parsed))
        
        except Exception as e:
            logger.error("packet_processing_failed", error=str(e))

    def _parse_packet(self, packet) -> Optional[Dict]:
        """
        Parse raw packet into structured dictionary.
        
        Returns dictionary with:
            - timestamp
            - src_ip, dst_ip
            - src_port, dst_port
            - protocol
            - packet_size
            - ttl, flags
            - payload_length
            - raw_payload (if present)
        """
        try:
            parsed = {
                "timestamp": datetime.utcnow().isoformat(),
                "packet_size": len(packet),
            }
            
            # Ethernet layer
            if Ether in packet:
                parsed["src_mac"] = packet[Ether].src
                parsed["dst_mac"] = packet[Ether].dst
            
            # IP layer
            if IP in packet:
                parsed["src_ip"] = packet[IP].src
                parsed["dst_ip"] = packet[IP].dst
                parsed["ttl"] = packet[IP].ttl
                parsed["ip_version"] = packet[IP].version
            
            # TCP
            if TCP in packet:
                parsed["protocol"] = "TCP"
                parsed["src_port"] = packet[TCP].sport
                parsed["dst_port"] = packet[TCP].dport
                parsed["flags"] = str(packet[TCP].flags)
                parsed["seq"] = packet[TCP].seq
                parsed["ack"] = packet[TCP].ack
                parsed["window"] = packet[TCP].window
            
            # UDP
            elif UDP in packet:
                parsed["protocol"] = "UDP"
                parsed["src_port"] = packet[UDP].sport
                parsed["dst_port"] = packet[UDP].dport
                parsed["length"] = packet[UDP].len
            
            # ICMP
            elif ICMP in packet:
                parsed["protocol"] = "ICMP"
                parsed["icmp_type"] = packet[ICMP].type
                parsed["icmp_code"] = packet[ICMP].code
            
            # ARP
            elif ARP in packet:
                parsed["protocol"] = "ARP"
                parsed["arp_op"] = packet[ARP].op  # 1=request, 2=reply
                parsed["arp_hwsrc"] = packet[ARP].hwsrc
                parsed["arp_psrc"] = packet[ARP].psrc
                parsed["arp_hwdst"] = packet[ARP].hwdst
                parsed["arp_pdst"] = packet[ARP].pdst
            
            # DNS
            if DNS in packet:
                parsed["protocol"] = "DNS"
                parsed["dns_id"] = packet[DNS].id
                parsed["dns_qr"] = packet[DNS].qr  # 0=query, 1=response
                if packet[DNS].qd:
                    parsed["dns_query"] = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
            
            # HTTP
            if HTTPRequest in packet:
                parsed["protocol"] = "HTTP"
                parsed["http_method"] = packet[HTTPRequest].Method.decode('utf-8', errors='ignore')
                parsed["http_host"] = packet[HTTPRequest].Host.decode('utf-8', errors='ignore')
                parsed["http_path"] = packet[HTTPRequest].Path.decode('utf-8', errors='ignore')
            
            # Raw payload
            if Raw in packet:
                parsed["payload_length"] = len(packet[Raw].load)
                parsed["payload_preview"] = packet[Raw].load[:100].hex()
            else:
                parsed["payload_length"] = 0
            
            return parsed
        
        except Exception as e:
            logger.debug("packet_parse_failed", error=str(e))
            return None

    def get_buffered_packets(self, count: Optional[int] = None) -> List[Dict]:
        """
        Retrieve packets from buffer.
        
        Args:
            count: Number of packets to retrieve (None = all)
        
        Returns:
            List of parsed packet dictionaries
        """
        with self._buffer_lock:
            if count is None:
                packets = list(self.packet_buffer)
                self.packet_buffer.clear()
            else:
                packets = [self.packet_buffer.popleft() for _ in range(min(count, len(self.packet_buffer)))]
        
        return packets

    def get_statistics(self) -> Dict:
        """Get capture statistics."""
        return {
            **self.stats,
            "buffer_size": len(self.packet_buffer),
            "capture_active": self._capture_active
        }

    async def capture_for_duration(self, duration_seconds: int) -> List[Dict]:
        """
        Capture packets for a specific duration.
        
        Args:
            duration_seconds: Duration to capture
        
        Returns:
            List of captured packets
        """
        self.start_capture()
        await asyncio.sleep(duration_seconds)
        self.stop_capture()
        return self.get_buffered_packets()
