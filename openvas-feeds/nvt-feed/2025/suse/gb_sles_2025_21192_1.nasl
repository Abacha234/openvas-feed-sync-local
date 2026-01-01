# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.21192.1");
  script_cve_id("CVE-2025-47910", "CVE-2025-47912", "CVE-2025-58183", "CVE-2025-58185", "CVE-2025-58186", "CVE-2025-58187", "CVE-2025-58188", "CVE-2025-58189", "CVE-2025-61723", "CVE-2025-61724", "CVE-2025-61725", "CVE-2025-61727", "CVE-2025-61729");
  script_tag(name:"creation_date", value:"2025-12-16 16:47:44 +0000 (Tue, 16 Dec 2025)");
  script_version("2025-12-17T05:46:28+0000");
  script_tag(name:"last_modification", value:"2025-12-17 05:46:28 +0000 (Wed, 17 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:21192-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:21192-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202521192-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245878");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247816");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1248082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249141");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1249985");
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
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254430");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254431");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2025-December/023549.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25' package(s) announced via the SUSE-SU-2025:21192-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.25 fixes the following issues:

Update to go1.25.5.

Security issues fixed:

- CVE-2025-61729: crypto/x509: excessive resource consumption in printing error string for host certificate validation
 (bsc#1254431).
- CVE-2025-61727: crypto/x509: excluded subdomain constraint doesn't preclude wildcard SAN (bsc#1254430).
- CVE-2025-61725: net/mail: excessive CPU consumption in ParseAddress (bsc#1251253).
- CVE-2025-61724: net/textproto: excessive CPU consumption in Reader.ReadResponse (bsc#1251262).
- CVE-2025-61723: encoding/pem: quadratic complexity when parsing some invalid inputs (bsc#1251256).
- CVE-2025-58189: crypto/tls: ALPN negotiation error contains attacker controlled information (bsc#1251255).
- CVE-2025-58188: crypto/x509: panic when validating certificates with DSA public keys (bsc#1251260).
- CVE-2025-58187: crypto/x509: quadratic complexity when checking name constraints (bsc#1251254).
- CVE-2025-58186: net/http: lack of limit when parsing cookies can cause memory exhaustion (bsc#1251259).
- CVE-2025-58185: encoding/asn1: pre-allocating memory when parsing DER payload can cause memory exhaustion
 (bsc#1251258).
- CVE-2025-58183: archive/tar: unbounded allocation when parsing GNU sparse map (bsc#1251261).
- CVE-2025-47912: net/url: insufficient validation of bracketed IPv6 hostnames (bsc#1251257).
- CVE-2025-47910: net/http: CrossOriginProtection insecure bypass patterns not limited to exact matches (bsc#1249141).

Other issues fixed and changes:

- Version 1.25.5:
 * go#76245 mime: FormatMediaType and ParseMediaType not compatible across 1.24 to 1.25
 * go#76360 os: on windows RemoveAll removing directories containing read-only files errors with unlinkat ... Access
 is denied, ReOpenFile error handling followup

- Version 1.25.4:
 * go#75480 cmd/link: linker panic and relocation errors with complex generics inlining
 * go#75775 runtime: build fails when run via QEMU for linux/amd64 running on linux/arm64
 * go#75790 crypto/internal/fips140/subtle: Go 1.25 subtle.xorBytes panic on MIPS
 * go#75832 net/url: ipv4 mapped ipv6 addresses should be valid in square brackets
 * go#75952 encoding/pem: regression when decoding blocks with leading garbage
 * go#75989 os: on windows RemoveAll removing directories containing read-only files errors with unlinkat ... Access
 is denied
 * go#76010 cmd/compile: any(func(){})==any(func(){}) does not panic but should
 * go#76029 pem/encoding: malformed line endings can cause panics

- Version 1.25.3:
 * go#75861 crypto/x509: TLS validation fails for FQDNs with trailing dot
 * go#75777 spec: Go1.25 spec should be dated closer to actual release date

- Version 1.25.2:
 * go#75111 os, syscall: volume handles with FILE_FLAG_OVERLAPPED fail when calling ReadAt
 * go#75116 os: Root.MkdirAll can return 'file exists' when called concurrently on the same path
 * go#75139 os: Root.OpenRoot sets incorrect name, losing ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'go1.25' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP applications 16.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-libstd", rpm:"go1.25-libstd~1.25.5~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.5~160000.1.1", rls:"SLES16.0.0"))) {
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
