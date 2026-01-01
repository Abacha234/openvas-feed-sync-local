# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4477.1");
  script_cve_id("CVE-2025-62348", "CVE-2025-62349");
  script_tag(name:"creation_date", value:"2025-12-19 15:00:01 +0000 (Fri, 19 Dec 2025)");
  script_version("2025-12-19T15:41:09+0000");
  script_tag(name:"last_modification", value:"2025-12-19 15:41:09 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4477-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP5|SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4477-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254477-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227207");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250520");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1250755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251776");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252244");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254257");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023618.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'salt' package(s) announced via the SUSE-SU-2025:4477-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for salt fixes the following issues:

- Security issues fixed:

 - CVE-2025-62349: Added minimum_auth_version to enforce security (bsc#1254257)
 - CVE-2025-62348: Fixed Junos module yaml loader (bsc#1254256)
 - Backport security fixes for vendored tornado
 * BDSA-2024-3438
 * BDSA-2024-3439
 * BDSA-2024-9026

- Other changes and bugs fixed:

 - Fixed TLS and x509 modules for OSes with older cryptography module
 - Fixed Salt for Python > 3.11 (bsc#1252285) (bsc#1252244)
 * Use external tornado on Python > 3.11
 * Make tls and x509 to use python-cryptography
 * Remove usage of spwd
 - Fixed payload signature verification on Tumbleweed (bsc#1251776)
 - Fixed broken symlink on migration to Leap 16.0 (bsc#1250755)
 - Fixed known_hosts error on gitfs (bsc#1250520) (bsc#1227207)
 - Improved SL Micro 6.2 detection with grains
 - Reverted requirement of M2Crypto >= 0.44.0 for SUSE Family distros
 - Set python-CherryPy as required for python-salt-testsuite");

  script_tag(name:"affected", value:"'salt' package(s) on SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python311-salt", rpm:"python311-salt~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-api", rpm:"salt-api~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-cloud", rpm:"salt-cloud~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-fish-completion", rpm:"salt-fish-completion~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-master", rpm:"salt-master~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-proxy", rpm:"salt-proxy~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-ssh", rpm:"salt-ssh~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-standalone-formulas-configuration", rpm:"salt-standalone-formulas-configuration~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-syndic", rpm:"salt-syndic~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150500.4.65.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"python3-salt", rpm:"python3-salt~3006.0~150500.4.65.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt", rpm:"salt~3006.0~150500.4.65.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-bash-completion", rpm:"salt-bash-completion~3006.0~150500.4.65.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-doc", rpm:"salt-doc~3006.0~150500.4.65.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-minion", rpm:"salt-minion~3006.0~150500.4.65.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"salt-zsh-completion", rpm:"salt-zsh-completion~3006.0~150500.4.65.1", rls:"SLES15.0SP6"))) {
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
