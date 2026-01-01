# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21194.1");
  script_cve_id("CVE-2025-1057", "CVE-2025-13609");
  script_tag(name:"creation_date", value:"2025-12-16 16:47:44 +0000 (Tue, 16 Dec 2025)");
  script_version("2025-12-17T05:46:28+0000");
  script_tag(name:"last_modification", value:"2025-12-17 05:46:28 +0000 (Wed, 17 Dec 2025)");
  script_tag(name:"cvss_base", value:"7.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:P/I:C/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-24 18:15:49 +0000 (Mon, 24 Nov 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21194-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21194-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521194-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1237153");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254199");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023547.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keylime' package(s) announced via the SUSE-SU-2025:21194-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for keylime fixes the following issues:

Update to version 7.13.0+40.

Security issues fixed:

- CVE-2025-13609: possible agent identity takeover due to registrar allowing the registration of agents with duplicate
 UUIDs (bsc#1254199).
- CVE-2025-1057: registrar denial-of-service due to backward incompatibility in database type handling (bsc#1237153).

Other issues fixed and changes:

- Version 7.13.0+40:
 * Include new attestation information fields (#1818)
 * Fix Database race conditions and SQLAlchemy 2.0 compatibility (#1823)
 * push-model: require HTTPS for authentication and attestation endpoints
 * Fix operational_state tracking in push mode attestations
 * templates: add push model authentication config options to 2.5 templates
 * Security: Hash authentication tokens in logs
 * Fix stale IMA policy cache in verification
 * Fix authentication behavior on failed attestations for push mode
 * Add shared memory infrastructure for multiprocess communication
 * Add agent authentication (challenge/response) protocol for push mode
 * Add agent-driven (push) attestation protocol with PULL mode regression fixes (#1814)
 * docs: Fix man page RST formatting for rst2man compatibility (#1813)
 * Apply limit on keylime-policy workers
 * tpm: fix ECC signature parsing to support variable-length coordinates
 * tpm: fix ECC P-521 credential activation with consistent marshaling
 * tpm: fix ECC P-521 coordinate validation
 * Remove deprecated disabled_signing_algorithms configuration option (#1804)
 * algorithms: add support for specific RSA algorithms
 * algorithms: add support for specific ECC curve algorithms
 * Created manpage for keylime-policy and edited manpages for keylime verifier, registrar, agent
 * Manpage for keylime agent
 * Manpage for keylime verifier
 * Manpage for keylime registrar
 * Use constants for timeout and max retries defaults
 * verifier: Use timeout from `request_timeout` config option
 * revocation_notifier: Use timeout setting from config file
 * tenant: Set timeout when getting version from agent
 * verify/evidence: SEV-SNP evidence type/verifier
 * verify/evidence: Add evidence type to request JSON

- Version v7.13.0:
 * Avoid re-encoding certificate stored in DB
 * Revert 'models: Do not re-encode certificate stored in DB'
 * Revert 'registrar_agent: Use pyasn1 to parse PEM'
 * policy/sign: use print() when writing to /dev/stdout
 * registrar_agent: Use pyasn1 to parse PEM
 * models: Do not re-encode certificate stored in DB
 * mba: normalize vendor_db in EV_EFI_VARIABLE_AUTHORITY events
 * mb: support vendor_db as logged by newer shim versions
 * mb: support EV_EFI_HANDOFF_TABLES events on PCR1
 * Remove unnecessary configuration values
 * cloud_verifier_tornado: handle exception in notify_error()
 * requests_client: close the session at the end of the resource manager
 * Manpage for keylime_tenant (#1786)
 * Add 2.5 templates including ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'keylime' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"keylime-config", rpm:"keylime-config~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-firewalld", rpm:"keylime-firewalld~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-logrotate", rpm:"keylime-logrotate~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-registrar", rpm:"keylime-registrar~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tenant", rpm:"keylime-tenant~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-tpm_cert_store", rpm:"keylime-tpm_cert_store~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"keylime-verifier", rpm:"keylime-verifier~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python313-keylime", rpm:"python313-keylime~7.13.0+40~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
