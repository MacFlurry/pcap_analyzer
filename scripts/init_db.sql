-- ============================================
-- PostgreSQL Initialization Script
-- PCAP Analyzer Database Setup
-- ============================================

-- Enable UUID extension for unique identifiers
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto for cryptographic functions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Optional: Enable pg_trgm for better full-text search
-- CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ============================================
-- Database Schema
-- ============================================
-- The actual schema will be created by Alembic migrations
-- This file is for extensions and initial setup only

-- Log successful initialization
DO $$
BEGIN
    RAISE NOTICE 'PostgreSQL initialization complete for pcap_analyzer database';
    RAISE NOTICE 'Extensions enabled: uuid-ossp, pgcrypto';
    RAISE NOTICE 'Ready for Alembic migrations';
END $$;
