# Password Vault Management System - SQL Phase

This folder contains the PostgreSQL database layer for the educational Password Vault Management System.

## Included files

- `00_setup.sql` - entry point that runs the full build in order
- `01_schema.sql` - schema, tables, keys, checks, and constraints
- `02_functions_procedures.sql` - reusable functions and stored procedures
- `03_triggers_views.sql` - triggers and reporting views
- `04_indexes.sql` - performance indexes
- `05_seed_data.sql` - sample data for demonstrations and analytics
- `06_analytics_queries.sql` - portfolio-style analytic queries

## Suggested run order

Use PostgreSQL and run `00_setup.sql` from `psql`, or execute the files in order if your client does not support `\ir` includes.

## Notes

- Password values are stored as encrypted strings or hashes, not plaintext.
- The schema is normalized and includes roles, permissions, audit logging, sharing, and security alert tracking.
- The project is intentionally educational and does not implement client-side encryption.
