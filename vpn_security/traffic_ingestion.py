"""
Traffic Ingestion Layer - Network Flow Metadata Collection

Collects network traffic metadata for security analysis without storing payload data.
Focuses on behavioral characteristics, timing patterns, and flow statistics.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from collections import deque
import structlog

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
    from scapy.layers.inet import ICMP
    from scapy.layers.tls.all import TLS
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


logger = structlog.get_logger(__name__)


@dataclass
class FlowMetadata:
    """Metadata for a network flow (no payload data stored)"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float
    packet_count: int = 0
    total_bytes: int = 0
    
    # Behavioral features
    packet_sizes: list[int] = field(default_factory=list)
    inter_arrival_times: list[float] = field(default_factory=list)
    tcp_flags: list[str] = field(default_factory=list)
    
    # TLS/Encryption indicators
    is_encrypted: bool = False
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    sni_hostname: Optional[str] = None
    
    # Statistical features
    avg_packet_size: float = 0.0
    packet_size_variance: float = 0.0
    avg_inter_arrival: float = 0.0
    burst_count: int = 0
    
    # Session persistence
    session_duration: float = 0.0
    is_bidirectional: bool = False
    upstream_bytes: int = 0
    downstream_bytes: int = 0


class TrafficIngestion:
    """
    Network traffic ingestion layer for metadata collection.
    
    Captures network flows and extracts behavioral features without
    storing sensitive payload data. Designed for real-time analysis.
    """
    
    def __init__(
        self,
        interface: str = "any",
        flow_timeout: int = 300,  # 5 minutes
        max_flows: int = 10000,
        enable_tls_analysis: bool = True
    ):
        """
        Initialize traffic ingestion layer.
        
        Args:
            interface: Network interface to capture from
            flow_timeout: Seconds before flow expires
            max_flows: Maximum concurrent flows to track
            enable_tls_analysis: Extract TLS metadata
        """
        self.interface = interface
        self.flow_timeout = flow_timeout
        self.max_flows = max_flows
        self.enable_tls_analysis = enable_tls_analysis
        
        # Flow tracking
        self.active_flows: dict[str, FlowMetadata] = {}
        self.flow_queue: deque = deque(maxlen=1000)
        
        # Statistics
        self.total_packets_captured = 0
        self.total_flows_created = 0
        self.flows_expired = 0
        
        # Control
        self.is_running = False
        self._capture_task: Optional[asyncio.Task] = None
        
        logger.info(
            "traffic_ingestion_initialized",
            interface=interface,
            flow_timeout=flow_timeout,
            max_flows=max_flows
        )
    
    async def start(self):
        """Start traffic capture"""
        if not SCAPY_AVAILABLE:
            logger.error("scapy_not_available", msg="Cannot start traffic ingestion")
            raise RuntimeError("Scapy library required for traffic capture")
        
        self.is_running = True
        self._capture_task = asyncio.create_task(self._capture_loop())
        logger.info("traffic_ingestion_started", interface=self.interface)
    
    async def stop(self):
        """Stop traffic capture"""
        self.is_running = False
        if self._capture_task:
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass
        logger.info("traffic_ingestion_stopped")
    
    async def _capture_loop(self):
        """Main capture loop running in background"""
        try:
            # Run packet capture in executor to avoid blocking
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                self._capture_packets
            )
        except asyncio.CancelledError:
            logger.info("capture_loop_cancelled")
        except Exception as e:
            logger.error("capture_loop_error", error=str(e))
    
    def _capture_packets(self):
        """Capture packets using Scapy (blocking operation)"""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            logger.error("packet_capture_error", error=str(e))
    
    def _process_packet(self, packet):
        """Process individual packet and update flow metadata"""
        try:
            self.total_packets_captured += 1
            
            # Extract basic packet info
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            protocol = ""
            src_port = 0
            dst_port = 0
            
            # Determine protocol and ports
            if packet.haslayer(TCP):
                protocol = "TCP"
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
            elif packet.haslayer(UDP):
                protocol = "UDP"
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
            elif packet.haslayer(ICMP):
                protocol = "ICMP"
            else:
                protocol = "OTHER"
            
            # Create flow ID
            flow_id = self._create_flow_id(
                ip_layer.src, ip_layer.dst,
                src_port, dst_port, protocol
            )
            
            # Get or create flow
            current_time = time.time()
            
            if flow_id in self.active_flows:
                flow = self.active_flows[flow_id]
                
                # Update flow statistics
                previous_seen = flow.last_seen
                flow.packet_count += 1
                flow.total_bytes += len(packet)
                flow.last_seen = current_time
                
                # Track packet size
                packet_size = len(packet)
                flow.packet_sizes.append(packet_size)
                
                # Track inter-arrival time
                if len(flow.packet_sizes) > 1:
                    inter_arrival = max(current_time - previous_seen, 0.0)
                    flow.inter_arrival_times.append(inter_arrival)

                # Mark flow as bidirectional when reverse direction appears.
                if ip_layer.src != flow.src_ip:
                    flow.is_bidirectional = True
                
                # Track TCP flags
                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    flow.tcp_flags.append(str(flags))
                
                # Detect bursts (rapid packets)
                if len(flow.inter_arrival_times) > 0:
                    recent_intervals = flow.inter_arrival_times[-10:]
                    if len(recent_intervals) >= 3:
                        avg_recent = sum(recent_intervals) / len(recent_intervals)
                        if avg_recent < 0.01:  # < 10ms = burst
                            flow.burst_count += 1
                
            else:
                # Create new flow
                if len(self.active_flows) >= self.max_flows:
                    self._cleanup_old_flows(current_time)
                
                flow = FlowMetadata(
                    flow_id=flow_id,
                    src_ip=ip_layer.src,
                    dst_ip=ip_layer.dst,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                    start_time=current_time,
                    last_seen=current_time,
                    packet_count=1,
                    total_bytes=len(packet),
                    packet_sizes=[len(packet)]
                )
                
                self.active_flows[flow_id] = flow
                self.total_flows_created += 1
            
            # Extract TLS metadata if enabled
            if self.enable_tls_analysis and packet.haslayer(TLS):
                self._extract_tls_metadata(packet, flow)
            
            # Calculate session duration
            flow.session_duration = flow.last_seen - flow.start_time
            
            # Calculate statistical features
            if len(flow.packet_sizes) > 1:
                flow.avg_packet_size = sum(flow.packet_sizes) / len(flow.packet_sizes)
                variance = sum((x - flow.avg_packet_size) ** 2 for x in flow.packet_sizes)
                flow.packet_size_variance = variance / len(flow.packet_sizes)
            
            if len(flow.inter_arrival_times) > 0:
                flow.avg_inter_arrival = sum(flow.inter_arrival_times) / len(flow.inter_arrival_times)
            
            # Add to processing queue
            if flow.packet_count % 10 == 0:  # Queue every 10th packet
                self.flow_queue.append(flow)
        
        except Exception as e:
            logger.error("packet_processing_error", error=str(e))
    
    def _create_flow_id(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> str:
        """Create unique flow identifier"""
        # Bidirectional flow ID (normalized)
        if src_ip < dst_ip:
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-{protocol}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-{protocol}"
    
    def _extract_tls_metadata(self, packet, flow: FlowMetadata):
        """Extract TLS handshake metadata without decrypting"""
        try:
            tls_layer = packet[TLS]
            flow.is_encrypted = True
            
            # Extract TLS version
            if hasattr(tls_layer, 'version'):
                flow.tls_version = str(tls_layer.version)
            
            # Extract SNI hostname
            if hasattr(tls_layer, 'msg') and tls_layer.msg:
                for msg in tls_layer.msg:
                    if hasattr(msg, 'ext'):
                        for ext in msg.ext:
                            if hasattr(ext, 'servernames'):
                                for servername in ext.servernames:
                                    flow.sni_hostname = servername.servername.decode('utf-8')
            
            # Extract cipher suite
            if hasattr(tls_layer, 'cipher'):
                flow.cipher_suite = str(tls_layer.cipher)
        
        except Exception as e:
            logger.debug("tls_extraction_error", error=str(e))
    
    def _cleanup_old_flows(self, current_time: float):
        """Remove expired flows"""
        expired_flows = [
            flow_id for flow_id, flow in self.active_flows.items()
            if (current_time - flow.last_seen) > self.flow_timeout
        ]
        
        for flow_id in expired_flows:
            del self.active_flows[flow_id]
            self.flows_expired += 1
        
        logger.debug("flows_cleaned", expired_count=len(expired_flows))
    
    def get_flow(self, flow_id: str) -> Optional[FlowMetadata]:
        """Get flow metadata by ID"""
        return self.active_flows.get(flow_id)
    
    def get_recent_flows(self, limit: int = 100) -> list[FlowMetadata]:
        """Get most recent flows from queue"""
        return list(self.flow_queue)[-limit:]
    
    def get_all_flows(self) -> list[FlowMetadata]:
        """Get all active flows"""
        return list(self.active_flows.values())
    
    def get_statistics(self) -> dict[str, Any]:
        """Get ingestion statistics"""
        return {
            "total_packets_captured": self.total_packets_captured,
            "total_flows_created": self.total_flows_created,
            "active_flows": len(self.active_flows),
            "flows_expired": self.flows_expired,
            "is_running": self.is_running,
            "interface": self.interface
        }
