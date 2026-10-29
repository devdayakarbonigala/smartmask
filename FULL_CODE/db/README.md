# db

`schema.sql` is the schema of the synthetic demo database. `python -m smartmask.seed` creates it
(`data/bank.db`, plus PostgreSQL when `SMARTMASK_PG_ADMIN_DSN` is set). The data itself is generated with
a fixed seed, so no database file is committed.

To use the organisers' Saffron Bank pack instead, point `SMARTMASK_SQLITE` at its `saffron_bank.db`
(or `SMARTMASK_PG_DSN` at its docker-compose database). The scanner tags the columns on first use.
