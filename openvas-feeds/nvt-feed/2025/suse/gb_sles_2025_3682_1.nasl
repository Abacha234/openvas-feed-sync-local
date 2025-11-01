# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.3682.1");
  script_cve_id("CVE-2025-47912", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58186", "CVE-2025-58187", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61724", "CVE-2025-61725");
  script_tag(name:"creation_date", value:"2025-10-22 04:15:56 +0000 (Wed, 22 Oct 2025)");
  script_version("2025-10-22T05:39:59+0000");
  script_tag(name:"last_modification", value:"2025-10-22 05:39:59 +0000 (Wed, 22 Oct 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:3682-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:3682-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20253682-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1236217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251253");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251254");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251255");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251257");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251258");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251259");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251261");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1251262");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-October/042220.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.24' package(s) announced via the SUSE-SU-2025:3682-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.24 fixes the following issues:

go1.24.9 (released 2025-10-13) includes fixes to the crypto/x509 package. (bsc#1236217)

* crypto/x509: TLS validation fails for FQDNs with trailing dot

go1.24.8 (released 2025-10-07) includes security fixes to the archive/tar, crypto/tls, crypto/x509, encoding/asn1,
encoding/pem, net/http, net/mail, net/textproto, and net/url packages, as well as bug fixes to the compiler, the linker, and the debug/pe, net/http, os, and sync/atomic packages.
(bsc#1236217)

 CVE-2025-58189 CVE-2025-61725 CVE-2025-58188 CVE-2025-58185 CVE-2025-58186 CVE-2025-61723 CVE-2025-58183 CVE-2025-47912 CVE-2025-58187 CVE-2025-61724:

 * bsc#1251255 CVE-2025-58189: crypto/tls: ALPN negotiation error contains attacker controlled information
 * bsc#1251253 CVE-2025-61725: net/mail: excessive CPU consumption in ParseAddress
 * bsc#1251260 CVE-2025-58188: crypto/x509: panic when validating certificates with DSA public keys
 * bsc#1251258 CVE-2025-58185: encoding/asn1: pre-allocating memory when parsing DER payload can cause memory exhaustion
 * bsc#1251259 CVE-2025-58186: net/http: lack of limit when parsing cookies can cause memory exhaustion
 * bsc#1251256 CVE-2025-61723: encoding/pem: quadratic complexity when parsing some invalid inputs
 * bsc#1251261 CVE-2025-58183: archive/tar: unbounded allocation when parsing GNU sparse map
 * bsc#1251257 CVE-2025-47912: net/url: insufficient validation of bracketed IPv6 hostnames
 * bsc#1251254 CVE-2025-58187: crypto/x509: quadratic complexity when checking name constraints
 * bsc#1251262 CVE-2025-61724: net/textproto: excessive CPU consumption in Reader.ReadResponse
 * os: Root.OpenRoot sets incorrect name, losing prefix of original root
 * debug/pe: pe.Open fails on object files produced by llvm-mingw 21
 * cmd/link: panic on riscv64 with CGO enabled due to empty container symbol
 * net: new test TestIPv4WriteMsgUDPAddrPortTargetAddrIPVersion fails on plan9
 * os: new test TestOpenFileCreateExclDanglingSymlink fails on Plan 9
 * crypto/internal/fips140/rsa: requires a panic if self-tests fail
 * net/http: internal error: connCount underflow
 * cmd/compile: internal compiler error with GOEXPERIMENT=cgocheck2 on github.com/leodido/go-urn
 * sync/atomic: comment for Uintptr.Or incorrectly describes return value");

  script_tag(name:"affected", value:"'go1.24' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.24", rpm:"go1.24~1.24.9~150000.1.42.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-doc", rpm:"go1.24-doc~1.24.9~150000.1.42.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-race", rpm:"go1.24-race~1.24.9~150000.1.42.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.24", rpm:"go1.24~1.24.9~150000.1.42.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-doc", rpm:"go1.24-doc~1.24.9~150000.1.42.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-race", rpm:"go1.24-race~1.24.9~150000.1.42.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.24", rpm:"go1.24~1.24.9~150000.1.42.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-doc", rpm:"go1.24-doc~1.24.9~150000.1.42.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.24-race", rpm:"go1.24-race~1.24.9~150000.1.42.1", rls:"SLES15.0SP5"))) {
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
