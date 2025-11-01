# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.03524.1");
  script_cve_id("CVE-2025-47910");
  script_tag(name:"creation_date", value:"2025-10-13 04:13:03 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-14T05:39:29+0000");
  script_tag(name:"last_modification", value:"2025-10-14 05:39:29 +0000 (Tue, 14 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:03524-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:03524-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202503524-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249141");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25-openssl' package(s) announced via the SUSE-SU-2025:03524-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.25-openssl fixes the following issues:

Update to version 1.25.1, released 2025-09-03 (bsc#1244485).

Security issues fixed:

 - CVE-2025-47910: net/http: `CrossOriginProtection` insecure bypass patterns not limited to exact matches (bsc#1249141).

 Other issues fixed:

 - go#74822 cmd/go: 'get toolchain@latest' should ignore release candidates
 - go#74999 net: WriteMsgUDPAddrPort should accept IPv4-mapped IPv6 destination addresses on IPv4 UDP sockets
 - go#75008 os/exec: TestLookPath fails on plan9 after CL 685755
 - go#75021 testing/synctest: bubble not terminating
 - go#75083 os: File.Seek doesn't set the correct offset with Windows overlapped handles");

  script_tag(name:"affected", value:"'go1.25-openssl' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl", rpm:"go1.25-openssl~1.25.1~150000.1.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-doc", rpm:"go1.25-openssl-doc~1.25.1~150000.1.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-race", rpm:"go1.25-openssl-race~1.25.1~150000.1.6.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl", rpm:"go1.25-openssl~1.25.1~150000.1.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-doc", rpm:"go1.25-openssl-doc~1.25.1~150000.1.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-race", rpm:"go1.25-openssl-race~1.25.1~150000.1.6.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl", rpm:"go1.25-openssl~1.25.1~150000.1.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-doc", rpm:"go1.25-openssl-doc~1.25.1~150000.1.6.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-openssl-race", rpm:"go1.25-openssl-race~1.25.1~150000.1.6.1", rls:"SLES15.0SP5"))) {
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
