"""
Base analyzer class providing interface consistency for all analyzers.

All analyzers should inherit from BaseAnalyzer to ensure a consistent
interface and proper error handling.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from scapy.packet import Packet
import logging

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """
    Abstract base class for all network traffic analyzers.

    Provides a consistent interface and common functionality for all analyzers.
    All concrete analyzer classes should inherit from this base class.

    The analyzer lifecycle:
    1. __init__(): Initialize analyzer with configuration
    2. process_packet(): Called for each packet in the capture
    3. finalize(): Called after all packets processed
    4. get_results(): Return analysis results as dictionary
    """

    @abstractmethod
    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """
        Process a single packet.

        This method is called for each packet in the capture file.
        Implementations should be efficient as this is called many times.

        Args:
            packet: Scapy packet object to process
            packet_num: Sequential packet number (0-indexed)

        Raises:
            ValueError: If packet is invalid or cannot be processed
        """
        pass

    @abstractmethod
    def finalize(self) -> Dict[str, Any]:
        """
        Finalize analysis and return results.

        Called after all packets have been processed via process_packet().
        Should perform any final calculations and return complete results.

        Returns:
            Dictionary containing analysis results

        Example:
            {
                'total_packets': 1000,
                'findings': [...],
                'statistics': {...}
            }
        """
        pass

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyze a list of packets (convenience method).

        Default implementation calls process_packet() for each packet,
        then calls finalize(). Can be overridden for custom behavior.

        Args:
            packets: List of Scapy packet objects

        Returns:
            Dictionary containing analysis results

        Raises:
            ValueError: If packets list is invalid
        """
        if not isinstance(packets, list):
            raise ValueError("packets must be a list")

        for i, packet in enumerate(packets):
            try:
                self.process_packet(packet, i)
            except Exception as e:
                # Log error but continue processing
                # Subclasses can override this behavior
                self._handle_packet_error(packet, i, e)

        return self.finalize()

    def _handle_packet_error(self, packet: Packet, packet_num: int,
                            error: Exception) -> None:
        """
        Handle errors during packet processing.

        Default implementation logs the error and continues. Override to customize
        error handling behavior (e.g., collecting errors, raising, etc.).

        Args:
            packet: Packet that caused the error
            packet_num: Packet number
            error: Exception that was raised
        """
        # Default: log error and continue
        # Subclasses can override to customize error handling
        logger.debug(
            f"{self.__class__.__name__}: Error processing packet #{packet_num}: {error}",
            exc_info=False
        )

    def get_results(self) -> Dict[str, Any]:
        """
        Get analysis results (alias for finalize).

        Some analyzers use get_results() instead of finalize().
        This provides compatibility.

        Returns:
            Dictionary containing analysis results
        """
        return self.finalize()

    def validate_packet(self, packet: Packet) -> bool:
        """
        Validate that a packet is suitable for this analyzer.

        Override this method to add analyzer-specific validation.
        Default implementation accepts all packets.

        Args:
            packet: Packet to validate

        Returns:
            bool: True if packet is valid for this analyzer
        """
        return packet is not None
