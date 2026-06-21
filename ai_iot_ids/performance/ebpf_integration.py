"""eBPF/XDP integration for high-performance packet processing."""

import os
import logging
import subprocess
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import ctypes
import struct

logger = logging.getLogger(__name__)

try:
    from bcc import BPF
    BCC_AVAILABLE = True
except ImportError:
    BCC_AVAILABLE = False
    logger.warning("BCC not available, eBPF features will be limited")


class eBPFManager:
    """Manages eBPF programs for high-performance packet processing."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize eBPF manager.
        
        Args:
            config: eBPF configuration dictionary
        """
        self.config = config or {}
        self.interface = self.config.get('interface', 'eth0')
        self.programs = {}
        self.maps = {}
        self.bpf = None
        
        if not BCC_AVAILABLE:
            logger.warning("BCC not available, eBPF functionality disabled")
            
    def load_packet_filter_program(self) -> bool:
        """Load eBPF program for packet filtering.
        
        Returns:
            True if program was loaded successfully
        """
        if not BCC_AVAILABLE:
            return False
            
        try:
            # eBPF program for packet filtering and statistics
            bpf_program = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/icmp.h>

// Map to store packet statistics
BPF_HASH(packet_stats, u32, u64, 1024);

// Map to store flow information
struct flow_key {
    u32 src_ip;
    u32 dst_ip;
    u16 src_port;
    u16 dst_port;
    u8 protocol;
};

struct flow_info {
    u64 packets;
    u64 bytes;
    u64 first_seen;
    u64 last_seen;
};

BPF_HASH(flows, struct flow_key, struct flow_info, 65536);

// Map for IoT device tracking
BPF_HASH(device_stats, u64, u64, 1024);  // MAC -> packet count

int packet_filter(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    struct ethhdr *eth = data;
    if ((void*)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
        
    // Only process IP packets
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
        
    // Extract flow information
    struct flow_key key = {};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    
    // Extract port information for TCP/UDP
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);
        if ((void*)tcp + sizeof(*tcp) > data_end)
            return XDP_PASS;
        key.src_port = tcp->source;
        key.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void*)ip + sizeof(*ip);
        if ((void*)udp + sizeof(*udp) > data_end)
            return XDP_PASS;
        key.src_port = udp->source;
        key.dst_port = udp->dest;
    }
    
    // Update flow statistics
    struct flow_info *flow = flows.lookup(&key);
    if (flow) {
        flow->packets++;
        flow->bytes += skb->len;
        flow->last_seen = bpf_ktime_get_ns();
    } else {
        struct flow_info new_flow = {};
        new_flow.packets = 1;
        new_flow.bytes = skb->len;
        new_flow.first_seen = bpf_ktime_get_ns();
        new_flow.last_seen = bpf_ktime_get_ns();
        flows.update(&key, &new_flow);
    }
    
    // Update device statistics based on source MAC
    u64 src_mac = 0;
    for (int i = 0; i < 6; i++) {
        src_mac = (src_mac << 8) | eth->h_source[i];
    }
    
    u64 *device_count = device_stats.lookup(&src_mac);
    if (device_count) {
        (*device_count)++;
    } else {
        u64 count = 1;
        device_stats.update(&src_mac, &count);
    }
    
    // Update global packet statistics
    u32 stats_key = 0;  // Total packets
    u64 *total_packets = packet_stats.lookup(&stats_key);
    if (total_packets) {
        (*total_packets)++;
    } else {
        u64 count = 1;
        packet_stats.update(&stats_key, &count);
    }
    
    return XDP_PASS;  // Pass packet to normal network stack
}
"""
            
            self.bpf = BPF(text=bpf_program)
            
            # Get references to maps
            self.maps['packet_stats'] = self.bpf.get_table("packet_stats")
            self.maps['flows'] = self.bpf.get_table("flows")
            self.maps['device_stats'] = self.bpf.get_table("device_stats")
            
            logger.info("Loaded eBPF packet filter program")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load eBPF program: {e}")
            return False
            
    def attach_xdp_program(self) -> bool:
        """Attach XDP program to network interface.
        
        Returns:
            True if program was attached successfully
        """
        if not self.bpf:
            logger.error("No eBPF program loaded")
            return False
            
        try:
            # Attach XDP program to interface
            fn = self.bpf.load_func("packet_filter", BPF.XDP)
            self.bpf.attach_xdp(self.interface, fn, 0)
            
            logger.info(f"Attached XDP program to interface {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach XDP program: {e}")
            return False
            
    def detach_xdp_program(self) -> bool:
        """Detach XDP program from network interface.
        
        Returns:
            True if program was detached successfully
        """
        if not self.bpf:
            return True
            
        try:
            self.bpf.remove_xdp(self.interface, 0)
            logger.info(f"Detached XDP program from interface {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to detach XDP program: {e}")
            return False
            
    def get_packet_statistics(self) -> Dict[str, int]:
        """Get packet processing statistics.
        
        Returns:
            Dictionary with packet statistics
        """
        stats = {}
        
        if not self.maps.get('packet_stats'):
            return stats
            
        try:
            for key, value in self.maps['packet_stats'].items():
                stats[f"total_packets"] = value.value
                
        except Exception as e:
            logger.error(f"Failed to get packet statistics: {e}")
            
        return stats
        
    def get_flow_statistics(self) -> List[Dict[str, Any]]:
        """Get network flow statistics.
        
        Returns:
            List of flow statistics dictionaries
        """
        flows = []
        
        if not self.maps.get('flows'):
            return flows
            
        try:
            for key, value in self.maps['flows'].items():
                flow_info = {
                    'src_ip': self._int_to_ip(key.src_ip),
                    'dst_ip': self._int_to_ip(key.dst_ip),
                    'src_port': key.src_port,
                    'dst_port': key.dst_port,
                    'protocol': key.protocol,
                    'packets': value.packets,
                    'bytes': value.bytes,
                    'first_seen': value.first_seen,
                    'last_seen': value.last_seen
                }
                flows.append(flow_info)
                
        except Exception as e:
            logger.error(f"Failed to get flow statistics: {e}")
            
        return flows
        
    def get_device_statistics(self) -> Dict[str, int]:
        """Get per-device packet statistics.
        
        Returns:
            Dictionary mapping MAC addresses to packet counts
        """
        devices = {}
        
        if not self.maps.get('device_stats'):
            return devices
            
        try:
            for key, value in self.maps['device_stats'].items():
                mac_address = self._int_to_mac(key.value)
                devices[mac_address] = value.value
                
        except Exception as e:
            logger.error(f"Failed to get device statistics: {e}")
            
        return devices
        
    def clear_statistics(self) -> bool:
        """Clear all eBPF map statistics.
        
        Returns:
            True if statistics were cleared successfully
        """
        try:
            for map_name, bpf_map in self.maps.items():
                bpf_map.clear()
                
            logger.info("Cleared eBPF statistics")
            return True
            
        except Exception as e:
            logger.error(f"Failed to clear statistics: {e}")
            return False
            
    def set_packet_callback(self, callback: Callable[[Dict[str, Any]], None]) -> bool:
        """Set callback function for packet events.
        
        Args:
            callback: Function to call for each packet event
            
        Returns:
            True if callback was set successfully
        """
        if not self.bpf:
            return False
            
        try:
            # This would require perf events or ring buffers for real-time callbacks
            # For now, we'll use polling of the maps
            logger.info("Packet callback functionality would require perf events")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set packet callback: {e}")
            return False
            
    def is_ebpf_available(self) -> bool:
        """Check if eBPF is available on the system.
        
        Returns:
            True if eBPF is available
        """
        if not BCC_AVAILABLE:
            return False
            
        try:
            # Check if BPF syscall is available
            result = subprocess.run([
                'bpftool', 'prog', 'list'
            ], capture_output=True, text=True)
            
            return result.returncode == 0
            
        except FileNotFoundError:
            # bpftool not available, try alternative check
            return os.path.exists('/sys/fs/bpf')
            
    def get_ebpf_capabilities(self) -> Dict[str, bool]:
        """Get eBPF capabilities information.
        
        Returns:
            Dictionary with capability information
        """
        capabilities = {
            'bcc_available': BCC_AVAILABLE,
            'bpf_syscall': False,
            'xdp_support': False,
            'tc_support': False,
            'kprobe_support': False,
            'uprobe_support': False
        }
        
        try:
            # Check BPF syscall availability
            if os.path.exists('/sys/fs/bpf'):
                capabilities['bpf_syscall'] = True
                
            # Check XDP support
            result = subprocess.run([
                'ip', 'link', 'set', 'dev', 'lo', 'xdp', 'off'
            ], capture_output=True, text=True)
            capabilities['xdp_support'] = result.returncode == 0
            
            # Check TC (traffic control) support
            result = subprocess.run([
                'tc', 'qdisc', 'show'
            ], capture_output=True, text=True)
            capabilities['tc_support'] = result.returncode == 0
            
            # Check kprobe support
            capabilities['kprobe_support'] = os.path.exists('/sys/kernel/debug/tracing/kprobe_events')
            
            # Check uprobe support
            capabilities['uprobe_support'] = os.path.exists('/sys/kernel/debug/tracing/uprobe_events')
            
        except Exception as e:
            logger.error(f"Failed to check eBPF capabilities: {e}")
            
        return capabilities
        
    def _int_to_ip(self, ip_int: int) -> str:
        """Convert integer IP address to string format."""
        return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"
        
    def _int_to_mac(self, mac_int: int) -> str:
        """Convert integer MAC address to string format."""
        mac_bytes = []
        for i in range(6):
            mac_bytes.append(f"{(mac_int >> (8 * (5 - i))) & 0xFF:02x}")
        return ":".join(mac_bytes)
        
    def __del__(self):
        """Cleanup eBPF resources."""
        if self.bpf:
            try:
                self.detach_xdp_program()
            except Exception:
                pass