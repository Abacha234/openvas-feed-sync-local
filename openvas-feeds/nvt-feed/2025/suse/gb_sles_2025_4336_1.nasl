# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.4336.1");
  script_cve_id("CVE-2025-61727", "CVE-2025-61729");
  script_tag(name:"creation_date", value:"2025-12-11 12:28:02 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T15:41:28+0000");
  script_tag(name:"last_modification", value:"2025-12-12 15:41:28 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:4336-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:4336-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20254336-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254431");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023493.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25' package(s) announced via the SUSE-SU-2025:4336-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.25 fixes the following issues:

go1.25.5 (released 2025-12-02) includes two security fixes to the crypto/x509 package, as well as bug fixes to the mime and os packages.
(bsc#1244485)

 CVE-2025-61729 CVE-2025-61727:

 * go#76461 go#76445 bsc#1254431 security: fix CVE-2025-61729 crypto/x509: excessive resource consumption in printing error string for host certificate validation
 * go#76464 go#76442 bsc#1254430 security: fix CVE-2025-61727 crypto/x509: excluded subdomain constraint doesn't preclude wildcard SAN
 * go#76245 mime: FormatMediaType and ParseMediaType not compatible across 1.24 to 1.25
 * go#76360 os: on windows RemoveAll removing directories containing read-only files errors with unlinkat ... Access is denied, ReOpenFile error handling followup

- Packaging: Migrate from update-alternatives to libalternatives (bsc#1245878)

 * This is an optional migration controlled via prjconf definition
 with_libalternatives
 * If with_libalternatives is not defined packaging continues to
 use update-alternatives

go1.25.4 (released 2025-11-05) includes fixes to the compiler,
the runtime, and the crypto/subtle, encoding/pem, net/url, and os packages. (bsc#1244485)

 * go#75480 cmd/link: linker panic and relocation errors with complex generics inlining
 * go#75775 runtime: build fails when run via QEMU for linux/amd64 running on linux/arm64
 * go#75790 crypto/internal/fips140/subtle: Go 1.25 subtle.xorBytes panic on MIPS
 * go#75832 net/url: ipv4 mapped ipv6 addresses should be valid in square brackets
 * go#75952 encoding/pem: regression when decoding blocks with leading garbage
 * go#75989 os: on windows RemoveAll removing directories containing read-only files errors with unlinkat ... Access is denied
 * go#76010 cmd/compile: any(func(){})==any(func(){}) does not panic but should
 * go#76029 pem/encoding: malformed line endings can cause panics");

  script_tag(name:"affected", value:"'go1.25' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.5~150000.1.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.5~150000.1.23.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.5~150000.1.23.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.5~150000.1.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.5~150000.1.23.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.5~150000.1.23.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.5~150000.1.23.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.5~150000.1.23.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.5~150000.1.23.1", rls:"SLES15.0SP5"))) {
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
