#OpenVAS Feed Sync (GitLab)
This repository provides a centralized mirror of the OpenVAS/Greenbone community feeds, enabling organizations to:

Mirror the feeds outside of Greenbone’s infrastructure.
Distribute them to multiple OpenVAS scanners without overloading Greenbone’s servers.
Automate updates and deployments.

📂 Repository Structure
The repository keeps the same folder layout that OpenVAS expects:
openvas-feed-sync/
├── nvt-feed/ # Network Vulnerability Tests
├── scap-feed/ # SCAP data (vulnerability mappings)
├── cert-feed/ # CERT advisories
└── vt-feed/ # Vulnerability Test data
