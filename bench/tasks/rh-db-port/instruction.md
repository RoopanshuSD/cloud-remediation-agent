**[OPS-2231] App servers time out connecting to the database**

Since this morning's infrastructure change, app servers in `app-sg` time out connecting to the Postgres
database in `db-sg` on port 5432. Customer checkouts are failing.
