# Bug Report: User Deletion Leaves Orphaned Files on Disk

**Status**: Confirmed
**Severity**: Medium (Storage Leak)
**Priority**: High
**Version**: v4.26.1
**Type**: Bug - Data Integrity
**Reporter**: Manual QA Testing (User Deletion Flow)
**Date**: 2025-12-25

---

## Executive Summary

When an administrator deletes a user account, the database records (user and associated tasks) are properly deleted via CASCADE constraints. However, the physical files (PCAP uploads and generated reports) remain on disk, creating **orphaned files** that consume storage indefinitely. This is a **storage leak** that will grow over time as users are deleted.

**User Impact**: Medium - No functional impact, but causes unbounded storage growth in production.

---

## Bug Description

### Current Behavior (INCORRECT ❌)

1. Admin deletes user "obk" via Admin Panel
2. Database CASCADE deletes:
   - User record from `users` table ✅
   - All task records from `tasks` table ✅
   - All progress snapshots from `progress_snapshots` table ✅
   - All password history from `password_history` table ✅
3. **Files remain on disk** ❌:
   - PCAP files: `/data/uploads/{task_id}.pcap`
   - HTML reports: `/data/reports/{task_id}.html`
   - JSON reports: `/data/reports/{task_id}.json`

### Expected Behavior (CORRECT ✅)

When a user is deleted, **all associated files should be deleted** from disk to prevent storage leaks.

---

## Reproduction Steps

### Prerequisites
- Access to Admin Panel at http://pcap.local/admin
- At least one non-admin user with uploaded PCAP files
- SSH/kubectl access to verify file system

### Steps to Reproduce

1. **Create test user and upload PCAP**:
   ```bash
   # Register new user "testuser"
   curl -X POST http://pcap.local/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"username":"testuser","email":"test@example.com","password":"SecurePass123!"}'

   # Login as admin and approve user
   # Upload PCAP file as testuser
   # Note the task_id (e.g., "abc-123-def-456")
   ```

2. **Verify files exist on disk**:
   ```bash
   kubectl exec -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer -- \
     ls -lh /data/uploads/ | grep abc-123-def-456
   # Output: -rw-r--r-- 1 root root 2.3M Dec 25 15:30 abc-123-def-456.pcap

   kubectl exec -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer -- \
     ls -lh /data/reports/ | grep abc-123-def-456
   # Output:
   # -rw-r--r-- 1 root root 45K Dec 25 15:31 abc-123-def-456.html
   # -rw-r--r-- 1 root root 12K Dec 25 15:31 abc-123-def-456.json
   ```

3. **Delete user via Admin Panel**:
   ```javascript
   // In Admin Panel UI
   // 1. Click "Supprimer" button next to "testuser"
   // 2. Confirm deletion in dialog
   ```

4. **Verify database records deleted**:
   ```bash
   kubectl exec -n pcap-analyzer pcap-analyzer-postgresql-0 -- \
     psql -U pcap -d pcap_analyzer -c "SELECT * FROM users WHERE username='testuser';"
   # Output: 0 rows (user deleted) ✅

   kubectl exec -n pcap-analyzer pcap-analyzer-postgresql-0 -- \
     psql -U pcap -d pcap_analyzer -c "SELECT * FROM tasks WHERE task_id='abc-123-def-456';"
   # Output: 0 rows (task deleted via CASCADE) ✅
   ```

5. **Verify files STILL EXIST on disk** ❌:
   ```bash
   kubectl exec -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer -- \
     ls -lh /data/uploads/ | grep abc-123-def-456
   # Output: -rw-r--r-- 1 root root 2.3M Dec 25 15:30 abc-123-def-456.pcap
   # ❌ FILE STILL EXISTS (orphaned)

   kubectl exec -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer -- \
     ls -lh /data/reports/ | grep abc-123-def-456
   # Output:
   # -rw-r--r-- 1 root root 45K Dec 25 15:31 abc-123-def-456.html
   # -rw-r--r-- 1 root root 12K Dec 25 15:31 abc-123-def-456.json
   # ❌ FILES STILL EXIST (orphaned)
   ```

### Actual Test Case (Confirmed)

**User deleted**: `obk` (ID: `da73b171-8745-469d-95cd-6191ffbacad1`)

**Audit log**:
```json
{"timestamp": "2025-12-25 15:44:38,914", "level": "WARNING",
 "message": "🗑️  AUDIT: Admin admin deleted user obk (id: da73b171-8745-469d-95cd-6191ffbacad1)"}
```

**Database verification**:
```sql
-- User deleted ✅
SELECT id, username FROM users WHERE username = 'obk';
-- (0 rows)

-- Tasks deleted via CASCADE ✅
SELECT task_id FROM tasks WHERE owner_id = 'da73b171-8745-469d-95cd-6191ffbacad1';
-- (0 rows)
```

**File system** (expected to have orphaned files, but user had no uploads in this test case).

---

## Technical Analysis

### Root Cause

**File**: `app/api/routes/auth.py:676-754`

The `delete_user` endpoint only deletes database records, **not the physical files**:

```python
@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: User = Depends(get_current_admin_user),
):
    # ... validation ...

    # ❌ BUG: Only deletes database record
    query, params = user_db.pool.translate_query(
        "DELETE FROM users WHERE id = ?",
        (user_id,),
    )
    await user_db.pool.execute(query, *params)

    logger.warning(f"🗑️  AUDIT: Admin {admin.username} deleted user {user.username} (id: {user_id})")

    # ❌ MISSING: No file cleanup
    # Files remain at:
    # - /data/uploads/{task_id}.pcap
    # - /data/reports/{task_id}.html
    # - /data/reports/{task_id}.json

    return {"message": f"User {user.username} deleted successfully"}
```

### Database Schema Analysis

**CASCADE constraints** properly delete database records:

```sql
-- Foreign key from tasks table
FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
```

**When user is deleted**:
- `users` table: Row deleted ✅
- `tasks` table: Rows deleted via CASCADE ✅
- `progress_snapshots` table: Rows deleted via CASCADE (fk_progress_snapshots_task_id) ✅
- `password_history` table: Rows deleted via CASCADE (fk_password_history_user_id) ✅

**BUT**: Filesystem is not aware of database CASCADE - **files remain**.

### File Naming Convention

**Files are named by `task_id` (UUID)**:

1. **PCAP uploads** (`app/api/routes/upload.py:148`):
   ```python
   upload_path = UPLOADS_DIR / f"{task_id}{Path(sanitized_filename).suffix}"
   # Example: /data/uploads/abc-123-def-456.pcap
   ```

2. **HTML reports** (`app/services/analyzer.py:325`):
   ```python
   html_path = self.reports_dir / f"{task_id}.html"
   # Example: /data/reports/abc-123-def-456.html
   ```

3. **JSON reports** (`app/services/analyzer.py:326`):
   ```python
   json_path = self.reports_dir / f"{task_id}.json"
   # Example: /data/reports/abc-123-def-456.json
   ```

**To delete files**: Query all `task_id`s for the user before deletion, then delete corresponding files.

---

## Impact Assessment

### Storage Impact

**Scenario**: Production system with 100 users over 1 year

| Metric | Value |
|--------|-------|
| Average PCAP size | 50 MB |
| Average uploads per user | 20 |
| User churn rate | 10% per year |
| Users deleted per year | 10 users |
| Orphaned files per deleted user | 20 PCAP + 40 reports (HTML+JSON) |
| **Total orphaned storage per year** | **10 GB PCAP + 200 MB reports** |

Over 3 years: **~30 GB of orphaned files** (unbounded growth).

### Operational Impact

1. **Cost**: Wasted cloud storage costs (AWS EBS, Azure Disk, etc.)
2. **Performance**: Degraded backup/snapshot performance (more data to backup)
3. **Compliance**: GDPR/CCPA requires deletion of user data - **orphaned files may contain user PII**
4. **Debugging**: Orphaned files make disk usage analysis confusing

### Security Impact

**GDPR/CCPA Compliance** ⚠️:
- PCAP files may contain network traffic with user identifiable information
- Retaining files after user deletion violates "Right to be Forgotten"
- **Legal risk** if user requests data deletion

---

## Proposed Solution

### Solution 1: Delete Files in `delete_user` Endpoint (RECOMMENDED)

**Implementation**:

```python
# app/api/routes/auth.py:732-754 (modified)
@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    admin: User = Depends(get_current_admin_user),
):
    """Delete a user account and all associated files (admin only)."""
    user_db = get_user_db_service()
    db_service = get_db_service()

    # Get user to delete
    user = await user_db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"User {user_id} not found")

    # Prevent self-deletion
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    # Prevent deleting other admins
    if user.role == UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="Cannot delete admin accounts")

    # ✅ NEW: Get all tasks for this user to delete associated files
    user_tasks = await db_service.get_user_tasks(user_id, limit=10000)

    # ✅ NEW: Delete physical files before deleting database records
    data_dir = Path(os.getenv("DATA_DIR", "/data"))
    uploads_dir = data_dir / "uploads"
    reports_dir = data_dir / "reports"

    files_deleted = {"uploads": 0, "reports": 0}
    errors = []

    for task in user_tasks:
        task_id = task.task_id

        # Delete PCAP file
        pcap_files = list(uploads_dir.glob(f"{task_id}.*"))
        for pcap_file in pcap_files:
            try:
                pcap_file.unlink()
                files_deleted["uploads"] += 1
                logger.info(f"Deleted PCAP: {pcap_file}")
            except Exception as e:
                errors.append(f"Failed to delete {pcap_file}: {e}")
                logger.error(f"Error deleting {pcap_file}: {e}")

        # Delete HTML report
        html_file = reports_dir / f"{task_id}.html"
        if html_file.exists():
            try:
                html_file.unlink()
                files_deleted["reports"] += 1
                logger.info(f"Deleted HTML report: {html_file}")
            except Exception as e:
                errors.append(f"Failed to delete {html_file}: {e}")
                logger.error(f"Error deleting {html_file}: {e}")

        # Delete JSON report
        json_file = reports_dir / f"{task_id}.json"
        if json_file.exists():
            try:
                json_file.unlink()
                files_deleted["reports"] += 1
                logger.info(f"Deleted JSON report: {json_file}")
            except Exception as e:
                errors.append(f"Failed to delete {json_file}: {e}")
                logger.error(f"Error deleting {json_file}: {e}")

    # Delete user from database (CASCADE will delete tasks, progress, password_history)
    try:
        query, params = user_db.pool.translate_query(
            "DELETE FROM users WHERE id = ?",
            (user_id,),
        )
        await user_db.pool.execute(query, *params)

        logger.warning(
            f"🗑️  AUDIT: Admin {admin.username} deleted user {user.username} "
            f"(id: {user_id}, files: {files_deleted['uploads']} uploads, "
            f"{files_deleted['reports']} reports)"
        )

        return {
            "message": f"User {user.username} deleted successfully",
            "user_id": user_id,
            "username": user.username,
            "files_deleted": files_deleted,
            "errors": errors if errors else None,
        }

    except Exception as e:
        logger.error(f"Error deleting user {user_id}: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to delete user: {str(e)}",
        )
```

**Pros**:
- Simple and immediate
- Atomic operation (files deleted before database records)
- No additional infrastructure

**Cons**:
- Blocking operation (may take time for users with many files)
- If file deletion fails, database deletion still proceeds (partial failure)

---

### Solution 2: Asynchronous Cleanup with Background Task (ALTERNATIVE)

**Implementation**:

```python
from fastapi import BackgroundTasks

async def cleanup_user_files(user_id: str, username: str, task_ids: list[str]):
    """Background task to delete user files."""
    data_dir = Path(os.getenv("DATA_DIR", "/data"))
    uploads_dir = data_dir / "uploads"
    reports_dir = data_dir / "reports"

    files_deleted = {"uploads": 0, "reports": 0}

    for task_id in task_ids:
        # Delete PCAP
        for pcap_file in uploads_dir.glob(f"{task_id}.*"):
            try:
                pcap_file.unlink()
                files_deleted["uploads"] += 1
            except Exception as e:
                logger.error(f"Error deleting {pcap_file}: {e}")

        # Delete reports
        for report_file in [reports_dir / f"{task_id}.html", reports_dir / f"{task_id}.json"]:
            if report_file.exists():
                try:
                    report_file.unlink()
                    files_deleted["reports"] += 1
                except Exception as e:
                    logger.error(f"Error deleting {report_file}: {e}")

    logger.info(
        f"Background cleanup completed for user {username}: "
        f"{files_deleted['uploads']} uploads, {files_deleted['reports']} reports deleted"
    )

@router.delete("/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    background_tasks: BackgroundTasks,
    admin: User = Depends(get_current_admin_user),
):
    # ... validation ...

    # Get tasks for background cleanup
    user_tasks = await db_service.get_user_tasks(user_id, limit=10000)
    task_ids = [task.task_id for task in user_tasks]

    # Delete user from database
    await user_db.pool.execute(...)

    # Schedule background cleanup
    background_tasks.add_task(cleanup_user_files, user_id, user.username, task_ids)

    return {"message": "User deleted, file cleanup in progress"}
```

**Pros**:
- Non-blocking (fast API response)
- Better UX for users with many files

**Cons**:
- More complex
- Files deleted AFTER database deletion (window where files exist without metadata)
- No immediate confirmation of file deletion

---

### Solution 3: Periodic Cleanup Job (COMPLEMENTARY)

**Add to existing CleanupScheduler** (`app/services/cleanup.py`):

```python
async def cleanup_orphaned_files(self):
    """Delete files that no longer have corresponding task records."""
    logger.info("Starting orphaned file cleanup...")

    data_dir = Path(os.getenv("DATA_DIR", "/data"))
    uploads_dir = data_dir / "uploads"
    reports_dir = data_dir / "reports"

    # Get all task_ids from database
    valid_task_ids = set()
    query = "SELECT task_id FROM tasks"
    rows = await self.db_service.pool.fetch_all(query)
    for row in rows:
        valid_task_ids.add(str(row["task_id"]))

    # Check uploads directory
    for file_path in uploads_dir.glob("*"):
        task_id = file_path.stem  # Filename without extension
        if task_id not in valid_task_ids:
            try:
                file_path.unlink()
                logger.info(f"Deleted orphaned upload: {file_path}")
            except Exception as e:
                logger.error(f"Error deleting orphaned file {file_path}: {e}")

    # Check reports directory
    for file_path in reports_dir.glob("*"):
        task_id = file_path.stem
        if task_id not in valid_task_ids:
            try:
                file_path.unlink()
                logger.info(f"Deleted orphaned report: {file_path}")
            except Exception as e:
                logger.error(f"Error deleting orphaned file {file_path}: {e}")

    logger.info("Orphaned file cleanup complete")

# Schedule in __init__
self.scheduler.add_job(
    self.cleanup_orphaned_files,
    "interval",
    days=1,
    id="cleanup_orphaned_files",
    name="Cleanup orphaned files (no task record)",
)
```

**Pros**:
- Safety net for any orphaned files (not just from user deletion)
- Handles edge cases (failed uploads, crashes, etc.)
- Can be run independently

**Cons**:
- Not immediate (runs daily)
- Additional database queries

---

## Recommended Implementation Strategy

### Phase 1: Immediate Fix (v4.27.0)
1. Implement **Solution 1** (delete files in endpoint) - Simple and effective
2. Add unit tests for file deletion
3. Add integration tests for user deletion flow

### Phase 2: Safety Net (v4.27.0 or v4.28.0)
4. Implement **Solution 3** (periodic cleanup job) - Catches orphaned files from any source
5. Add monitoring/alerting for orphaned file count

### Phase 3: Optimization (Future)
6. Consider **Solution 2** (background tasks) if user deletion becomes slow

---

## Testing Requirements

### Unit Tests (`tests/unit/test_user_deletion.py`)

```python
async def test_delete_user_removes_files(tmp_path):
    """Test that deleting a user removes associated files."""
    # Setup: Create user, task, and mock files
    uploads_dir = tmp_path / "uploads"
    reports_dir = tmp_path / "reports"
    uploads_dir.mkdir()
    reports_dir.mkdir()

    task_id = "test-task-123"
    (uploads_dir / f"{task_id}.pcap").write_text("mock pcap")
    (reports_dir / f"{task_id}.html").write_text("mock html")
    (reports_dir / f"{task_id}.json").write_text("mock json")

    # Act: Delete user
    # ... call delete_user endpoint ...

    # Assert: Files deleted
    assert not (uploads_dir / f"{task_id}.pcap").exists()
    assert not (reports_dir / f"{task_id}.html").exists()
    assert not (reports_dir / f"{task_id}.json").exists()

async def test_delete_user_partial_failure_handling():
    """Test that user deletion succeeds even if some files fail to delete."""
    # Setup: Mock file deletion to raise PermissionError for one file
    # Act: Delete user
    # Assert: User deleted from database despite file deletion error
    # Assert: Error logged but does not block deletion
```

### Integration Tests (`tests/integration/test_user_deletion_integration.py`)

```python
@pytest.mark.asyncio
async def test_full_user_deletion_flow(api_client, admin_headers, user_db, tmp_path):
    """Test complete user deletion including database and files."""
    # 1. Create user and upload PCAP
    user = await user_db.create_user(...)
    # ... upload PCAP, generate reports ...

    # 2. Verify files exist
    assert pcap_file.exists()
    assert html_file.exists()

    # 3. Delete user via API
    response = await api_client.delete(f"/api/admin/users/{user.id}", headers=admin_headers)
    assert response.status_code == 200

    # 4. Verify database records deleted
    assert await user_db.get_user_by_id(user.id) is None

    # 5. Verify files deleted
    assert not pcap_file.exists()
    assert not html_file.exists()
    assert not json_file.exists()
```

### Manual QA Checklist

- [ ] Create user, upload PCAP, generate reports
- [ ] Verify files exist on disk before deletion
- [ ] Delete user via Admin Panel
- [ ] Verify user deleted from database
- [ ] Verify tasks deleted from database
- [ ] Verify PCAP file deleted from `/data/uploads/`
- [ ] Verify HTML report deleted from `/data/reports/`
- [ ] Verify JSON report deleted from `/data/reports/`
- [ ] Check logs for file deletion confirmation
- [ ] Test with user who has 0 uploads (edge case)
- [ ] Test with user who has 100+ uploads (performance)
- [ ] Test file deletion failure (read-only filesystem) - should log error but not fail

---

## Security Considerations

### 1. GDPR/CCPA Compliance

**Critical**: This bug violates data privacy regulations.

- **GDPR Article 17**: "Right to erasure (right to be forgotten)"
- **CCPA Section 1798.105**: Consumer's right to deletion

**Remediation**: Implement file deletion to ensure complete data removal.

### 2. Path Traversal Prevention

**Risk**: If task_id is user-controlled, could delete unintended files.

**Mitigation**:
- Use UUID validation for task_id (already implemented)
- Use `Path.resolve()` and validate within directory bounds
- Log all file deletions for audit trail

```python
# Secure file deletion
def safe_delete(file_path: Path, allowed_dir: Path):
    resolved = file_path.resolve()
    if not str(resolved).startswith(str(allowed_dir.resolve())):
        raise ValueError(f"Path {file_path} outside allowed directory")
    resolved.unlink()
```

### 3. Audit Logging

**Requirement**: Log all file deletions for compliance and debugging.

```python
logger.warning(
    f"🗑️  FILE DELETE: Admin {admin.username} deleted {file_path} "
    f"(user: {user.username}, task: {task_id})"
)
```

---

## Monitoring and Alerting

### Metrics to Track

1. **Orphaned file count**: Files without corresponding task records
2. **Orphaned file size**: Total storage consumed by orphaned files
3. **User deletion file count**: Average files deleted per user deletion
4. **File deletion errors**: Count of failures during user deletion

### Prometheus Metrics (Future Enhancement)

```python
from prometheus_client import Counter, Gauge

orphaned_files_total = Gauge("orphaned_files_total", "Total orphaned files on disk")
user_deletion_files_deleted = Counter("user_deletion_files_deleted", "Files deleted during user deletion", ["type"])
user_deletion_errors = Counter("user_deletion_errors", "File deletion errors during user deletion")
```

---

## Related Issues and Dependencies

### Related Bugs

- **CleanupScheduler**: Already handles old PCAP/report deletion (by retention period)
- This bug is specific to **user-initiated deletion**, not time-based cleanup

### Dependencies

- None (standalone fix)

### Breaking Changes

- None (internal implementation only)

---

## Success Criteria

### Functional Success

- ✅ User deletion removes all PCAP files from `/data/uploads/`
- ✅ User deletion removes all HTML reports from `/data/reports/`
- ✅ User deletion removes all JSON reports from `/data/reports/`
- ✅ Database CASCADE deletion still works correctly
- ✅ File deletion errors are logged but do not block user deletion

### Performance Success

- ✅ User deletion with 10 files completes in < 5 seconds
- ✅ User deletion with 100 files completes in < 30 seconds
- ✅ No blocking operations that impact API responsiveness

### Compliance Success

- ✅ GDPR "Right to be Forgotten" compliance verified
- ✅ Audit logs capture all file deletions
- ✅ No orphaned files remain after user deletion

---

## Implementation Checklist

### Code Changes (v4.27.0)

- [ ] Modify `app/api/routes/auth.py::delete_user()` to delete files
- [ ] Add `get_user_tasks()` helper if needed (check if exists)
- [ ] Add error handling for file deletion failures
- [ ] Add detailed audit logging for file deletions
- [ ] Update docstring to reflect file deletion behavior

### Cleanup Job (v4.27.0 or v4.28.0)

- [ ] Add `cleanup_orphaned_files()` to `app/services/cleanup.py`
- [ ] Schedule daily job in CleanupScheduler
- [ ] Add logging for orphaned file detection

### Tests (v4.27.0)

- [ ] Unit tests for file deletion logic
- [ ] Integration tests for full user deletion flow
- [ ] Edge case tests (0 files, 1000+ files, permission errors)
- [ ] Manual QA with real PCAP uploads

### Documentation (v4.27.0)

- [ ] Update API documentation for DELETE /api/admin/users/{user_id}
- [ ] Add data retention policy documentation
- [ ] Update GDPR compliance documentation

### Deployment (v4.27.0)

- [ ] Test in staging with production-like data
- [ ] Monitor file deletion logs post-deployment
- [ ] Set up alerting for file deletion errors
- [ ] Verify no orphaned files remain after user deletions

---

## Questions for Stakeholders

1. **Retention Policy**: Should there be a grace period before file deletion (e.g., soft delete for 30 days)?
2. **Backup**: Should deleted files be archived before permanent deletion?
3. **Performance**: Is async file deletion preferred for users with many uploads?
4. **Alerting**: Should admins be notified if file deletion fails during user deletion?

---

## References

### Regulations

- [GDPR Article 17 - Right to erasure](https://gdpr-info.eu/art-17-gdpr/)
- [CCPA Section 1798.105 - Consumer's Right to Delete](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.105)

### Similar Implementations

- Django: Signals for post-deletion cleanup
- Rails: `after_destroy` callbacks with file deletion
- Laravel: Model events with storage facade

### Testing Tools

- `pytest-mock`: Mock filesystem operations
- `fakefs`: In-memory filesystem for testing
- `testcontainers`: Integration tests with real PostgreSQL

---

**End of Bug Report**
