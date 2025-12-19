"""
TCP State Machine Implementation (RFC 793 compliant).

This module implements a complete TCP state machine to accurately track
connection lifecycle and detect proper connection closure. This prevents
false positives in retransmission detection when ports are reused after
connection termination.

State Machine:
    CLOSED → LISTEN → SYN-SENT → SYN-RECEIVED → ESTABLISHED →
    FIN-WAIT-1 → FIN-WAIT-2 → TIME-WAIT → CLOSED

    Alternative paths:
    - ESTABLISHED → CLOSE-WAIT → LAST-ACK → CLOSED
    - FIN-WAIT-1 → CLOSING → TIME-WAIT → CLOSED
    - Any state → CLOSED (on RST)

Timeouts (RFC 793 compliant):
    - TIME-WAIT: 120 seconds (2×MSL, Maximum Segment Lifetime = 60s)
    - Connection Timeout: 300 seconds (5 minutes of inactivity)
    - FIN Timeout: 30 seconds (graceful close should complete quickly)

References:
    RFC 793: Transmission Control Protocol
    RFC 1122: Requirements for Internet Hosts
    RFC 6298: Computing TCP's Retransmission Timer
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple


class TCPState(Enum):
    """
    TCP connection states as defined in RFC 793, Section 3.2.

    State descriptions:
        CLOSED: No connection exists
        LISTEN: Server waiting for connection request
        SYN_SENT: Client sent SYN, waiting for SYN-ACK
        SYN_RECEIVED: Server received SYN, sent SYN-ACK, waiting for ACK
        ESTABLISHED: Connection established, data transfer phase
        FIN_WAIT_1: Sent FIN, waiting for ACK or FIN
        FIN_WAIT_2: Received ACK of our FIN, waiting for peer's FIN
        CLOSE_WAIT: Received peer's FIN, waiting for local close
        CLOSING: Both sides sent FIN simultaneously, waiting for ACKs
        LAST_ACK: Received peer's FIN, sent our FIN, waiting for final ACK
        TIME_WAIT: Waiting for 2×MSL to ensure remote received final ACK
    """
    CLOSED = "CLOSED"
    LISTEN = "LISTEN"
    SYN_SENT = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT_1 = "FIN_WAIT_1"
    FIN_WAIT_2 = "FIN_WAIT_2"
    CLOSE_WAIT = "CLOSE_WAIT"
    CLOSING = "CLOSING"
    LAST_ACK = "LAST_ACK"
    TIME_WAIT = "TIME_WAIT"

    def is_closed(self) -> bool:
        """Check if state represents a closed connection."""
        return self in (TCPState.CLOSED, TCPState.TIME_WAIT)

    def is_established(self) -> bool:
        """Check if connection is in data transfer phase."""
        return self == TCPState.ESTABLISHED

    def is_closing(self) -> bool:
        """Check if connection is in closing phase."""
        return self in (
            TCPState.FIN_WAIT_1,
            TCPState.FIN_WAIT_2,
            TCPState.CLOSE_WAIT,
            TCPState.CLOSING,
            TCPState.LAST_ACK,
            TCPState.TIME_WAIT,
        )


@dataclass
class TCPFlowState:
    """
    Tracks TCP connection state for a single flow (unidirectional).

    For bidirectional tracking, maintain two TCPFlowState objects:
    - One for client→server (forward)
    - One for server→client (reverse)

    Attributes:
        state: Current TCP state per RFC 793
        isn: Initial Sequence Number (from SYN packet)
        next_seq: Expected next sequence number
        max_seq_seen: Highest sequence number seen
        max_ack_seen: Highest ACK number seen (from peer)

        # FIN tracking
        fin_seq: Sequence number of our FIN packet (if sent)
        fin_sent: Whether we sent FIN
        fin_acked: Whether our FIN was ACKed by peer

        # Peer FIN tracking (in reverse direction)
        peer_fin_seq: Sequence number of peer's FIN packet (if received)
        peer_fin_received: Whether peer sent FIN
        peer_fin_acked: Whether we ACKed peer's FIN

        # Timestamps
        last_packet_time: Timestamp of last packet in this flow
        state_transition_time: Timestamp of last state transition
        time_wait_start: Timestamp when TIME-WAIT started (for timeout)

        # Connection closure tracking
        rst_seen: Whether RST was sent/received
        connection_closed: Whether connection is definitively closed
        closure_timestamp: When connection was closed
    """

    state: TCPState = TCPState.CLOSED
    isn: Optional[int] = None
    next_seq: Optional[int] = None
    max_seq_seen: Optional[int] = None
    max_ack_seen: Optional[int] = None

    # FIN tracking (our direction)
    fin_seq: Optional[int] = None
    fin_sent: bool = False
    fin_acked: bool = False

    # Peer FIN tracking (reverse direction)
    peer_fin_seq: Optional[int] = None
    peer_fin_received: bool = False
    peer_fin_acked: bool = False

    # Timestamps
    last_packet_time: float = 0.0
    state_transition_time: float = 0.0
    time_wait_start: Optional[float] = None

    # Connection closure
    rst_seen: bool = False
    connection_closed: bool = False
    closure_timestamp: Optional[float] = None


class TCPStateMachine:
    """
    RFC 793 compliant TCP state machine with timeout handling.

    This class manages TCP connection state transitions for both directions
    of a bidirectional flow, ensuring proper detection of connection closure
    to prevent false positives in retransmission detection.

    Usage:
        sm = TCPStateMachine()

        # Process each packet
        flow_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
        sm.process_packet(
            flow_key=flow_key,
            timestamp=pkt.time,
            tcp_flags={'SYN': True, 'ACK': False},
            seq=1000,
            ack=0,
            payload_len=0
        )

        # Check if connection is closed
        if sm.is_connection_closed(flow_key, current_time):
            # Reset retransmission tracking for this flow
            pass
    """

    # RFC 793 timeouts (configurable)
    TIME_WAIT_DURATION = 120.0  # 2×MSL (Maximum Segment Lifetime = 60s)
    CONNECTION_TIMEOUT = 300.0  # 5 minutes of inactivity
    FIN_TIMEOUT = 30.0  # Graceful close should complete quickly

    def __init__(
        self,
        time_wait_duration: float = 120.0,
        connection_timeout: float = 300.0,
        fin_timeout: float = 30.0,
    ):
        """
        Initialize TCP state machine.

        Args:
            time_wait_duration: TIME-WAIT duration in seconds (default: 120s)
            connection_timeout: Inactivity timeout in seconds (default: 300s)
            fin_timeout: FIN completion timeout in seconds (default: 30s)
        """
        self.TIME_WAIT_DURATION = time_wait_duration
        self.CONNECTION_TIMEOUT = connection_timeout
        self.FIN_TIMEOUT = fin_timeout

        # Flow state tracking: flow_key → TCPFlowState
        self._flow_states: Dict[str, TCPFlowState] = {}

        # Reverse flow mapping: flow_key → reverse_flow_key
        self._reverse_mapping: Dict[str, str] = {}

    def _get_reverse_key(self, flow_key: str) -> str:
        """
        Get reverse flow key for bidirectional tracking.

        Args:
            flow_key: Flow key in format "src_ip:src_port->dst_ip:dst_port"

        Returns:
            Reverse flow key in format "dst_ip:dst_port->src_ip:src_port"
        """
        if flow_key in self._reverse_mapping:
            return self._reverse_mapping[flow_key]

        # Parse flow key: "10.1.2.3:1234->10.5.6.7:80"
        parts = flow_key.split("->")
        if len(parts) != 2:
            return flow_key  # Invalid format, return as-is

        reverse_key = f"{parts[1]}->{parts[0]}"

        # Cache bidirectional mapping
        self._reverse_mapping[flow_key] = reverse_key
        self._reverse_mapping[reverse_key] = flow_key

        return reverse_key

    def _get_or_create_state(self, flow_key: str) -> TCPFlowState:
        """Get existing flow state or create new one."""
        if flow_key not in self._flow_states:
            self._flow_states[flow_key] = TCPFlowState()
        return self._flow_states[flow_key]

    def process_packet(
        self,
        flow_key: str,
        timestamp: float,
        tcp_flags: Dict[str, bool],
        seq: int,
        ack: int,
        payload_len: int,
    ) -> TCPState:
        """
        Process a TCP packet and update state machine.

        Args:
            flow_key: Flow identifier "src_ip:src_port->dst_ip:dst_port"
            timestamp: Packet timestamp
            tcp_flags: Dict with TCP flags {'SYN': bool, 'ACK': bool, 'FIN': bool, 'RST': bool}
            seq: TCP sequence number
            ack: TCP acknowledgment number
            payload_len: TCP payload length (in bytes)

        Returns:
            New TCP state after processing this packet
        """
        flow_state = self._get_or_create_state(flow_key)
        reverse_key = self._get_reverse_key(flow_key)
        reverse_state = self._get_or_create_state(reverse_key)

        # Extract flags
        is_syn = tcp_flags.get('SYN', False)
        is_ack = tcp_flags.get('ACK', False)
        is_fin = tcp_flags.get('FIN', False)
        is_rst = tcp_flags.get('RST', False)

        # Calculate logical length (RFC 793: SYN and FIN consume 1 seq number each)
        logical_len = payload_len
        if is_syn:
            logical_len += 1
        if is_fin:
            logical_len += 1

        # Update timestamp
        flow_state.last_packet_time = timestamp

        # Handle RST: Immediate connection closure (RFC 793, page 37)
        if is_rst:
            self._handle_rst(flow_key, reverse_key, timestamp)
            return flow_state.state

        # State transitions based on current state and flags
        current_state = flow_state.state

        if current_state == TCPState.CLOSED:
            if is_syn and not is_ack:
                # Client initiating connection: CLOSED → SYN-SENT
                flow_state.state = TCPState.SYN_SENT
                flow_state.isn = seq
                flow_state.next_seq = seq + logical_len
                flow_state.max_seq_seen = seq
                flow_state.state_transition_time = timestamp
            elif is_syn and is_ack:
                # Server responding to SYN: CLOSED → SYN-RECEIVED
                # (Happens when we don't see the initial SYN)
                flow_state.state = TCPState.SYN_RECEIVED
                flow_state.isn = seq
                flow_state.next_seq = seq + logical_len
                flow_state.max_seq_seen = seq
                flow_state.max_ack_seen = ack
                flow_state.state_transition_time = timestamp

        elif current_state == TCPState.SYN_SENT:
            if is_syn and is_ack:
                # Received SYN-ACK: SYN-SENT → SYN-RECEIVED
                # (We're seeing the reverse SYN-ACK)
                reverse_state.state = TCPState.SYN_RECEIVED
                reverse_state.isn = seq
                reverse_state.max_ack_seen = ack
                reverse_state.state_transition_time = timestamp
            elif is_ack and not is_syn:
                # Received final ACK: SYN-SENT → ESTABLISHED
                flow_state.state = TCPState.ESTABLISHED
                flow_state.max_ack_seen = ack
                flow_state.state_transition_time = timestamp

        elif current_state == TCPState.SYN_RECEIVED:
            if is_ack and not is_syn:
                # Received ACK of SYN-ACK: SYN-RECEIVED → ESTABLISHED
                flow_state.state = TCPState.ESTABLISHED
                flow_state.max_ack_seen = ack
                flow_state.state_transition_time = timestamp

        elif current_state == TCPState.ESTABLISHED:
            if is_fin:
                # Initiating close: ESTABLISHED → FIN-WAIT-1
                flow_state.state = TCPState.FIN_WAIT_1
                flow_state.fin_seq = seq
                flow_state.fin_sent = True
                flow_state.state_transition_time = timestamp

                # Mark peer as receiving our FIN
                reverse_state.peer_fin_seq = seq
                reverse_state.peer_fin_received = True

            # Update sequence tracking
            if seq + logical_len > (flow_state.max_seq_seen or 0):
                flow_state.max_seq_seen = seq + logical_len
            if is_ack and ack > (flow_state.max_ack_seen or 0):
                flow_state.max_ack_seen = ack

        elif current_state == TCPState.FIN_WAIT_1:
            if is_ack:
                # Check if this ACKs our FIN
                if flow_state.fin_seq is not None and ack > flow_state.fin_seq:
                    flow_state.fin_acked = True

                    # Check if peer also sent FIN (simultaneous close)
                    if flow_state.peer_fin_received:
                        # FIN-WAIT-1 → CLOSING (received FIN before ACK of our FIN)
                        flow_state.state = TCPState.CLOSING
                        flow_state.state_transition_time = timestamp
                    else:
                        # FIN-WAIT-1 → FIN-WAIT-2 (ACK of our FIN, waiting for peer FIN)
                        flow_state.state = TCPState.FIN_WAIT_2
                        flow_state.state_transition_time = timestamp

            if is_fin and not flow_state.peer_fin_received:
                # Received peer's FIN
                flow_state.peer_fin_seq = seq
                flow_state.peer_fin_received = True

                if flow_state.fin_acked:
                    # Already ACKed our FIN, now received peer FIN: → TIME-WAIT
                    flow_state.state = TCPState.TIME_WAIT
                    flow_state.time_wait_start = timestamp
                    flow_state.state_transition_time = timestamp
                else:
                    # Received peer FIN before ACK of our FIN: → CLOSING
                    flow_state.state = TCPState.CLOSING
                    flow_state.state_transition_time = timestamp

        elif current_state == TCPState.FIN_WAIT_2:
            if is_fin:
                # Received peer's FIN: FIN-WAIT-2 → TIME-WAIT
                flow_state.state = TCPState.TIME_WAIT
                flow_state.time_wait_start = timestamp
                flow_state.peer_fin_seq = seq
                flow_state.peer_fin_received = True
                flow_state.state_transition_time = timestamp

        elif current_state == TCPState.CLOSING:
            if is_ack:
                # Received ACK of our FIN in simultaneous close: CLOSING → TIME-WAIT
                if flow_state.fin_seq is not None and ack > flow_state.fin_seq:
                    flow_state.state = TCPState.TIME_WAIT
                    flow_state.time_wait_start = timestamp
                    flow_state.fin_acked = True
                    flow_state.state_transition_time = timestamp

        # Handle peer sending FIN (we receive FIN) - transitions to CLOSE-WAIT
        if is_fin and current_state == TCPState.ESTABLISHED:
            # This is handled in the ESTABLISHED case above
            # But we also need to update reverse direction
            reverse_state.state = TCPState.CLOSE_WAIT
            reverse_state.peer_fin_seq = seq
            reverse_state.peer_fin_received = True
            reverse_state.state_transition_time = timestamp

        # Update next expected sequence
        if logical_len > 0:
            flow_state.next_seq = seq + logical_len

        return flow_state.state

    def _handle_rst(self, flow_key: str, reverse_key: str, timestamp: float) -> None:
        """
        Handle RST packet: immediate connection closure.

        RFC 793, page 37: "If the RST bit is set then any outstanding RECEIVEs
        and SEND should receive 'reset' responses. All segment queues should be
        flushed. Users should also receive an unsolicited general 'connection reset'
        signal. Enter the CLOSED state, delete the TCB, and return."
        """
        # Mark both directions as closed
        for key in [flow_key, reverse_key]:
            if key in self._flow_states:
                state = self._flow_states[key]
                state.state = TCPState.CLOSED
                state.rst_seen = True
                state.connection_closed = True
                state.closure_timestamp = timestamp
                state.state_transition_time = timestamp

    def is_connection_closed(
        self,
        flow_key: str,
        current_time: float,
    ) -> bool:
        """
        Check if a connection is definitively closed and can be reset.

        A connection is considered closed if:
        1. RST was received (immediate closure)
        2. TIME-WAIT expired (after 2×MSL)
        3. Connection timed out due to inactivity
        4. FIN timeout expired (incomplete close)

        Args:
            flow_key: Flow identifier
            current_time: Current timestamp for timeout calculations

        Returns:
            True if connection is closed and state can be reset
        """
        if flow_key not in self._flow_states:
            return True  # No state = effectively closed

        flow_state = self._flow_states[flow_key]

        # Check 1: RST received (immediate closure)
        if flow_state.rst_seen or flow_state.connection_closed:
            return True

        # Check 2: TIME-WAIT expired
        if flow_state.state == TCPState.TIME_WAIT:
            if flow_state.time_wait_start is not None:
                elapsed = current_time - flow_state.time_wait_start
                if elapsed >= self.TIME_WAIT_DURATION:
                    # Mark as closed
                    flow_state.connection_closed = True
                    flow_state.closure_timestamp = current_time
                    return True

        # Check 3: Connection timeout (inactivity)
        if flow_state.last_packet_time > 0:
            idle_time = current_time - flow_state.last_packet_time
            if idle_time >= self.CONNECTION_TIMEOUT:
                # Connection stale, consider closed
                flow_state.connection_closed = True
                flow_state.closure_timestamp = current_time
                return True

        # Check 4: FIN timeout (incomplete close)
        if flow_state.fin_sent and not flow_state.fin_acked:
            fin_elapsed = current_time - flow_state.state_transition_time
            if fin_elapsed >= self.FIN_TIMEOUT:
                # FIN not ACKed within timeout, consider closed
                flow_state.connection_closed = True
                flow_state.closure_timestamp = current_time
                return True

        return False

    def should_reset_flow_state(
        self,
        flow_key: str,
        current_time: float,
        new_syn_seq: Optional[int] = None,
    ) -> bool:
        """
        Determine if flow state should be reset for retransmission tracking.

        This is the key method for preventing false positives. Reset when:
        1. Connection is definitively closed (see is_connection_closed)
        2. New SYN with different ISN (port reuse after close)
        3. No existing state (new connection)

        Args:
            flow_key: Flow identifier
            current_time: Current timestamp
            new_syn_seq: If this is a SYN packet, the sequence number (for ISN check)

        Returns:
            True if retransmission analyzer should reset state for this flow
        """
        # No existing state = new connection
        if flow_key not in self._flow_states:
            return True

        flow_state = self._flow_states[flow_key]

        # Check if connection is closed
        if self.is_connection_closed(flow_key, current_time):
            return True

        # Check for ISN mismatch (port reuse with different ISN)
        if new_syn_seq is not None and flow_state.isn is not None:
            if new_syn_seq != flow_state.isn:
                # Different ISN = new connection (port reuse)
                return True

        return False

    def reset_flow(self, flow_key: str) -> None:
        """
        Reset flow state (called after retransmission analyzer resets).

        Args:
            flow_key: Flow identifier to reset
        """
        if flow_key in self._flow_states:
            del self._flow_states[flow_key]

        # Also remove from reverse mapping
        if flow_key in self._reverse_mapping:
            reverse_key = self._reverse_mapping[flow_key]
            del self._reverse_mapping[flow_key]
            if reverse_key in self._reverse_mapping:
                del self._reverse_mapping[reverse_key]

    def get_state(self, flow_key: str) -> Optional[TCPState]:
        """
        Get current TCP state for a flow.

        Args:
            flow_key: Flow identifier

        Returns:
            Current TCP state, or None if no state exists
        """
        if flow_key not in self._flow_states:
            return None
        return self._flow_states[flow_key].state

    def get_flow_info(self, flow_key: str) -> Optional[Dict]:
        """
        Get detailed flow state information (for debugging/logging).

        Args:
            flow_key: Flow identifier

        Returns:
            Dictionary with flow state details, or None if no state exists
        """
        if flow_key not in self._flow_states:
            return None

        flow_state = self._flow_states[flow_key]
        return {
            'state': flow_state.state.value,
            'isn': flow_state.isn,
            'fin_sent': flow_state.fin_sent,
            'fin_acked': flow_state.fin_acked,
            'peer_fin_received': flow_state.peer_fin_received,
            'rst_seen': flow_state.rst_seen,
            'connection_closed': flow_state.connection_closed,
            'closure_timestamp': flow_state.closure_timestamp,
            'last_packet_time': flow_state.last_packet_time,
        }
