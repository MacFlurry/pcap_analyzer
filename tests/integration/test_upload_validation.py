import pytest
from httpx import AsyncClient
import os

@pytest.mark.asyncio
async def test_upload_ultimate_pcap_returns_validation_error(async_client: AsyncClient, ultimate_pcap_path):
    """Upload Ultimate PCAP should return 400 with validation details"""
    
    # Ensure file exists
    assert os.path.exists(ultimate_pcap_path)

    with open(ultimate_pcap_path, 'rb') as f:
        files = {'file': ('ultimate.pcapng', f, 'application/vnd.tcpdump.pcap')}
        response = await async_client.post('/api/upload', files=files)

    assert response.status_code == 400
    data = response.json()

    assert data['success'] is False
    assert 'validation_details' in data
    assert data['validation_details']['error_type'] == 'INVALID_TIMESTAMPS'
    assert len(data['validation_details']['detected_issues']) > 0
    assert len(data['validation_details']['suggestions']) > 0

@pytest.mark.asyncio
async def test_upload_valid_pcap_succeeds(async_client: AsyncClient, normal_pcap_path):
    """Upload valid PCAP should succeed"""
    
    # Ensure file exists
    assert os.path.exists(normal_pcap_path)

    with open(normal_pcap_path, 'rb') as f:
        files = {'file': ('normal.pcap', f, 'application/vnd.tcpdump.pcap')}
        response = await async_client.post('/api/upload', files=files)

    assert response.status_code == 202 # ACCEPTED
    data = response.json()

    assert data['task_id'] is not None
    assert 'validation_details' not in data
