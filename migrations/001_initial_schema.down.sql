-- Rollback initial schema

DROP TABLE IF EXISTS device_states;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS tenants;

DROP EXTENSION IF EXISTS "uuid-ossp";