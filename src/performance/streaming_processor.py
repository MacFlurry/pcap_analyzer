#!/usr/bin/env python3
"""
Streaming PCAP Processor for Large Files

Optimized packet processing with:
- Memory-efficient streaming (no full load)
- Chunked processing for large files
- Configurable memory limits
- Progress tracking
- Decompression bomb protection (OWASP ASVS 5.2.3, CWE-409)

Author: PCAP Analyzer Team
Sprint: 10 (Performance Optimization)
"""

import gc
import logging
import os
from collections.abc import Iterator
from typing import Any, List, Optional

from scapy.all import PcapReader
from scapy.packet import Packet

from ..utils.decompression_monitor import DecompressionMonitor, DecompressionBombError

logger = logging.getLogger(__name__)


class StreamingProcessor:
    """
    Memory-efficient streaming processor for large PCAP files.

    Features:
    - Processes packets in chunks to limit memory usage
    - Automatic garbage collection between chunks
    - Configurable chunk sizes based on file size
    - Progress callback support
    - Decompression bomb protection (OWASP ASVS 5.2.3, CWE-409)
    """

    # File size thresholds for different strategies
    SMALL_FILE_THRESHOLD = 100 * 1024 * 1024  # 100MB - load all in memory
    MEDIUM_FILE_THRESHOLD = 500 * 1024 * 1024  # 500MB - chunk processing
    LARGE_FILE_THRESHOLD = 2 * 1024 * 1024 * 1024  # 2GB - aggressive chunking

    # Chunk sizes for different file sizes
    SMALL_CHUNK_SIZE = 50000  # packets
    MEDIUM_CHUNK_SIZE = 20000  # packets
    LARGE_CHUNK_SIZE = 10000  # packets

    def __init__(
        self,
        pcap_file: str,
        enable_bomb_protection: bool = True,
        max_expansion_ratio: int = 1000,
        critical_expansion_ratio: int = 10000,
    ):
        """
        Initialize streaming processor.

        Args:
            pcap_file: Path to PCAP file
            enable_bomb_protection: Enable decompression bomb detection (default: True)
            max_expansion_ratio: Warning threshold for expansion ratio (default: 1000)
            critical_expansion_ratio: Critical threshold for expansion ratio (default: 10000)
        """
        self.pcap_file = pcap_file
        self.file_size = os.path.getsize(pcap_file)
        self.chunk_size = self._determine_chunk_size()
        self.processing_mode = self._determine_processing_mode()

        # Initialize decompression bomb monitor
        self.decompression_monitor = DecompressionMonitor(
            max_ratio=max_expansion_ratio, critical_ratio=critical_expansion_ratio, enabled=enable_bomb_protection
        )

    def _determine_processing_mode(self) -> str:
        """Determine best processing mode based on file size."""
        if self.file_size < self.SMALL_FILE_THRESHOLD:
            return "memory"  # Load all in memory
        elif self.file_size < self.MEDIUM_FILE_THRESHOLD:
            return "chunked"  # Process in chunks
        elif self.file_size < self.LARGE_FILE_THRESHOLD:
            return "streaming"  # Full streaming mode
        else:
            return "aggressive_streaming"  # Minimal memory mode

    def _determine_chunk_size(self) -> int:
        """Determine optimal chunk size based on file size."""
        if self.file_size < self.SMALL_FILE_THRESHOLD:
            return float("inf")  # No chunking
        elif self.file_size < self.MEDIUM_FILE_THRESHOLD:
            return self.SMALL_CHUNK_SIZE
        elif self.file_size < self.LARGE_FILE_THRESHOLD:
            return self.MEDIUM_CHUNK_SIZE
        else:
            return self.LARGE_CHUNK_SIZE

    def stream_packets(self, callback: Optional[callable] = None) -> Iterator[Packet]:
        """
        Stream packets from PCAP file with progress callback.

        SECURITY: Monitors for decompression bomb attacks (OWASP ASVS 5.2.3, CWE-409).

        Args:
            callback: Optional function called for each packet (packet, index)

        Yields:
            Scapy packet objects

        Raises:
            DecompressionBombError: If expansion ratio exceeds critical threshold
        """
        bytes_processed = 0

        with PcapReader(self.pcap_file) as reader:
            for i, packet in enumerate(reader):
                # Track bytes for decompression bomb detection
                bytes_processed += len(packet)

                # Check for decompression bomb every N packets (OWASP ASVS 5.2.3)
                if i % 10000 == 0 and i > 0:
                    try:
                        self.decompression_monitor.check_expansion_ratio(self.file_size, bytes_processed, i)
                    except DecompressionBombError:
                        logger.critical(
                            f"Decompression bomb detected at packet {i}. " f"Processing aborted for security."
                        )
                        raise

                if callback:
                    callback(packet, i)
                yield packet

    def stream_chunks(self, callback: Optional[callable] = None) -> Iterator[list[Packet]]:
        """
        Stream packets in chunks for memory-efficient processing.

        SECURITY: Monitors for decompression bomb attacks (OWASP ASVS 5.2.3, CWE-409).

        Args:
            callback: Optional function called after each chunk (chunk_idx, chunk_size)

        Yields:
            Lists of Scapy packets (chunks)

        Raises:
            DecompressionBombError: If expansion ratio exceeds critical threshold
        """
        chunk = []
        chunk_idx = 0
        packet_count = 0
        bytes_processed = 0

        with PcapReader(self.pcap_file) as reader:
            for packet in reader:
                chunk.append(packet)
                packet_count += 1
                bytes_processed += len(packet)

                # Check for decompression bomb every N packets (OWASP ASVS 5.2.3)
                if packet_count % 10000 == 0:
                    try:
                        self.decompression_monitor.check_expansion_ratio(self.file_size, bytes_processed, packet_count)
                    except DecompressionBombError:
                        logger.critical(
                            f"Decompression bomb detected at packet {packet_count}. "
                            f"Processing aborted for security."
                        )
                        raise

                if len(chunk) >= self.chunk_size:
                    # Yield full chunk
                    if callback:
                        callback(chunk_idx, len(chunk))

                    yield chunk

                    # Clear chunk and force garbage collection
                    chunk = []
                    chunk_idx += 1
                    gc.collect()

            # Yield remaining packets
            if chunk:
                if callback:
                    callback(chunk_idx, len(chunk))
                yield chunk

    def get_all_packets(self) -> list[Packet]:
        """
        Load all packets in memory (for small files only).

        SECURITY: Monitors for decompression bomb attacks (OWASP ASVS 5.2.3, CWE-409).

        Returns:
            List of all packets

        Raises:
            MemoryError: If file is too large
            DecompressionBombError: If expansion ratio exceeds critical threshold
        """
        if self.processing_mode != "memory":
            raise MemoryError(
                f"File too large ({self.file_size / (1024*1024):.1f}MB) "
                f"for full memory load. Use stream_packets() or stream_chunks() instead."
            )

        packets = []
        bytes_processed = 0

        with PcapReader(self.pcap_file) as reader:
            for i, packet in enumerate(reader):
                packets.append(packet)
                bytes_processed += len(packet)

                # Check for decompression bomb every N packets (OWASP ASVS 5.2.3)
                if i % 10000 == 0 and i > 0:
                    try:
                        self.decompression_monitor.check_expansion_ratio(self.file_size, bytes_processed, i)
                    except DecompressionBombError:
                        logger.critical(
                            f"Decompression bomb detected while loading all packets. "
                            f"Processing aborted for security."
                        )
                        raise

        return packets

    def count_packets(self) -> int:
        """
        Count total packets in file without loading into memory.

        Returns:
            Total packet count
        """
        count = 0
        with PcapReader(self.pcap_file) as reader:
            for _ in reader:
                count += 1
        return count

    def get_stats(self) -> dict:
        """
        Get processor statistics.

        Returns:
            Dictionary with processor stats
        """
        return {
            "file_path": self.pcap_file,
            "file_size_mb": self.file_size / (1024 * 1024),
            "processing_mode": self.processing_mode,
            "chunk_size": self.chunk_size if self.chunk_size != float("inf") else None,
            "recommended_mode": self._get_mode_description(),
        }

    def _get_mode_description(self) -> str:
        """Get human-readable processing mode description."""
        descriptions = {
            "memory": "Full memory load (file < 100MB)",
            "chunked": "Chunked processing (100MB-500MB)",
            "streaming": "Streaming mode (500MB-2GB)",
            "aggressive_streaming": "Aggressive streaming (>2GB)",
        }
        return descriptions.get(self.processing_mode, "Unknown")


class ChunkedAnalyzerRunner:
    """
    Runs analyzers in chunked mode for large files.
    Accumulates results across chunks.
    """

    def __init__(self, analyzers: list[Any], processor: StreamingProcessor):
        """
        Initialize chunked analyzer runner.

        Args:
            analyzers: List of analyzer objects
            processor: StreamingProcessor instance
        """
        self.analyzers = analyzers
        self.processor = processor

    def run(self, progress_callback: Optional[callable] = None) -> list[Any]:
        """
        Run all analyzers on chunked data.

        Args:
            progress_callback: Optional callback(chunk_idx, total_chunks, packets_processed)

        Returns:
            List of analyzer results
        """
        results = []
        total_packets = 0
        chunk_idx = 0

        for chunk in self.processor.stream_chunks():
            total_packets += len(chunk)

            # Run each analyzer on this chunk
            for analyzer in self.analyzers:
                if hasattr(analyzer, "analyze"):
                    analyzer.analyze(chunk)

            if progress_callback:
                progress_callback(chunk_idx, total_packets)

            chunk_idx += 1

            # Force garbage collection after each chunk
            del chunk
            gc.collect()

        # Finalize analyzers and collect results
        for analyzer in self.analyzers:
            if hasattr(analyzer, "finalize"):
                analyzer.finalize()
            if hasattr(analyzer, "get_results"):
                results.append(analyzer.get_results())

        return results
