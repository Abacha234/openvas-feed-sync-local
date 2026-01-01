# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4491.1");
  script_cve_id("CVE-2023-52969", "CVE-2023-52970", "CVE-2025-13699", "CVE-2025-21490", "CVE-2025-30693", "CVE-2025-30722");
  script_tag(name:"creation_date", value:"2025-12-22 04:28:20 +0000 (Mon, 22 Dec 2025)");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-27 16:03:10 +0000 (Fri, 27 Jun 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4491-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4491-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254491-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239151");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1243356");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254313");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023630.html");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-5-28-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-5-28-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-5-29-changelog/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb-10-5-29-release-notes/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mariadb' package(s) announced via the SUSE-SU-2025:4491-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for mariadb fixes the following issues:

Update to version 10.5.29.

Release notes and changelog:

- [links moved to references]

Security issues fixed:

- Version 10.5.28:
 * CVE-2025-21490: InnoDB issue allows high privileged attacker with network access to cause a hang or frequently
 repeatable crash of MySQL Server (bsc#1243356).

- Version 10.5.29:
 * CVE-2025-30693: InnoDB issue allows high privileged attacker with network access to gain unauthorized update, insert
 or delete access to data and cause repeatable crash in MySQL server (bsc#1249213).
 * CVE-2025-30722: mysqldump issue allows low privileged attacker with network access to gain unauthorized update,
 insert or delete access to data in MySQL Client (bsc#1249212).
 * CVE-2023-52969: crash with empty backtrace log in MariaDB Server (bsc#1239150).
 * CVE-2023-52970: crash in MariaDB Server when inserting from derived table containing insert target table
 (bsc#1239151).

- CVE-2025-13699: lack of proper validation of a user-supplied path prior to using it in file operations allows an
 attacker to execute code in the context of the current user (bsc#1254313).");

  script_tag(name:"affected", value:"'mariadb' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd-devel", rpm:"libmariadbd-devel~10.5.29~150300.3.55.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmariadbd19", rpm:"libmariadbd19~10.5.29~150300.3.55.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb", rpm:"mariadb~10.5.29~150300.3.55.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-client", rpm:"mariadb-client~10.5.29~150300.3.55.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-errormessages", rpm:"mariadb-errormessages~10.5.29~150300.3.55.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mariadb-tools", rpm:"mariadb-tools~10.5.29~150300.3.55.1", rls:"SLES15.0SP3"))) {
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
