"""Authentication and authorization for Husn.

Two roles:
  * admin    — full access (manage users, change defense state, apply updates).
  * employee — read-only access to telemetry, blocks, recipients, etc.

Storage is a single YAML file (default: <repo>/config/users.yml in dev,
/etc/husn/users.yml in production) with bcrypt-hashed passwords and a
persistent JWT signing secret. On first startup the file is created with
a default admin (`admin / admin@`) — change the password immediately.
"""
