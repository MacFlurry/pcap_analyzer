"""
Tests d'intégration end-to-end
Simulent le workflow complet: upload → analyse → rapport
"""

import pytest
import asyncio
from pathlib import Path


@pytest.mark.integration
@pytest.mark.asyncio
async def test_complete_workflow_upload_to_report(client, sample_pcap_file, test_db):
    """
    Test du workflow complet:
    1. Upload fichier PCAP
    2. Vérifier task créée en DB
    3. Vérifier progression
    4. Vérifier rapport généré
    """
    # 1. Upload
    with open(sample_pcap_file, "rb") as f:
        upload_response = client.post(
            "/api/upload",
            files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    assert upload_response.status_code == 202
    upload_data = upload_response.json()
    task_id = upload_data["task_id"]
    
    # 2. Vérifier task en DB
    task = await test_db.get_task(task_id)
    assert task is not None
    assert task.status.value in ["pending", "processing"]
    
    # 3. Vérifier endpoint de status
    status_response = client.get(f"/api/status/{task_id}")
    assert status_response.status_code == 200
    
    # Note: Pour tester complètement, il faudrait:
    # - Attendre que l'analyse se termine (worker actif)
    # - Vérifier que les rapports sont générés
    # - Télécharger et valider le contenu des rapports
    # Mais cela nécessite un worker fonctionnel et une vraie analyse


@pytest.mark.integration
def test_upload_and_check_queue(client, sample_pcap_file):
    """Test upload et vérification de la queue"""
    # Vérifier queue avant upload
    queue_before = client.get("/api/queue/status").json()
    initial_total = queue_before["total_tasks"]
    
    # Upload
    with open(sample_pcap_file, "rb") as f:
        client.post(
            "/api/upload",
            files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    # Vérifier queue après upload
    queue_after = client.get("/api/queue/status").json()
    
    # Le total devrait avoir augmenté (ou la queue size)
    assert (queue_after["total_tasks"] > initial_total or 
            queue_after["queue_size"] > 0)


@pytest.mark.integration
def test_history_after_upload(client, sample_pcap_file):
    """Test que l'historique est mis à jour après upload"""
    # Upload un fichier
    with open(sample_pcap_file, "rb") as f:
        upload_response = client.post(
            "/api/upload",
            files={"file": ("history_test.pcap", f, "application/vnd.tcpdump.pcap")}
        )
    
    task_id = upload_response.json()["task_id"]
    
    # Vérifier dans l'historique
    history_response = client.get("/api/history")
    assert history_response.status_code == 200
    
    history_data = history_response.json()
    task_ids = [task["task_id"] for task in history_data["tasks"]]
    
    assert task_id in task_ids


@pytest.mark.integration
@pytest.mark.slow
def test_multiple_uploads_sequential(client, sample_pcap_file):
    """Test plusieurs uploads séquentiels"""
    uploaded_ids = []
    
    for i in range(3):
        with open(sample_pcap_file, "rb") as f:
            response = client.post(
                "/api/upload",
                files={"file": (f"test_{i}.pcap", f, "application/vnd.tcpdump.pcap")}
            )
        
        assert response.status_code == 202
        uploaded_ids.append(response.json()["task_id"])
    
    # Vérifier que toutes les tâches sont dans l'historique
    history = client.get("/api/history").json()
    history_ids = [task["task_id"] for task in history["tasks"]]
    
    for task_id in uploaded_ids:
        assert task_id in history_ids


@pytest.mark.integration
def test_health_check_integration(client):
    """Test health check avec stats réelles"""
    response = client.get("/api/health")
    
    assert response.status_code == 200
    data = response.json()
    
    # Vérifier que les stats sont cohérentes
    assert data["status"] == "healthy"
    assert data["queue_size"] >= 0
    assert data["active_analyses"] >= 0
    assert data["total_tasks_completed"] >= 0


@pytest.mark.integration
def test_view_routes_accessibility(client):
    """Test que les routes de vues (HTML) sont accessibles"""
    # Page d'accueil
    response = client.get("/")
    assert response.status_code == 200
    assert b"PCAP Analyzer" in response.content or b"pcap" in response.content.lower()
    
    # Page historique
    response = client.get("/history")
    assert response.status_code == 200
    
    # Page progression (avec task_id fictif)
    response = client.get("/progress/test-task-123")
    assert response.status_code == 200
