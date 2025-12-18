-- Migration: Add progress tracking and heartbeat support
-- Date: 2025-12-18
-- Description: Adds progress_snapshots table and heartbeat columns to support
--              real progress persistence and OOMKilled pod detection

-- Add columns to tasks table for heartbeat and progress tracking
ALTER TABLE tasks ADD COLUMN last_heartbeat TIMESTAMP;
ALTER TABLE tasks ADD COLUMN progress_percent INTEGER DEFAULT 0;
ALTER TABLE tasks ADD COLUMN current_phase TEXT;

-- Create index for heartbeat queries (orphan detection)
CREATE INDEX IF NOT EXISTS idx_tasks_heartbeat ON tasks(last_heartbeat);

-- Create progress_snapshots table for progress history
CREATE TABLE IF NOT EXISTS progress_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    phase TEXT NOT NULL,  -- 'metadata', 'analysis', 'finalize'
    progress_percent INTEGER NOT NULL,
    packets_processed INTEGER,
    total_packets INTEGER,
    current_analyzer TEXT,
    message TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

-- Create indexes for progress_snapshots
CREATE INDEX IF NOT EXISTS idx_progress_task_id ON progress_snapshots(task_id);
CREATE INDEX IF NOT EXISTS idx_progress_timestamp ON progress_snapshots(timestamp);
