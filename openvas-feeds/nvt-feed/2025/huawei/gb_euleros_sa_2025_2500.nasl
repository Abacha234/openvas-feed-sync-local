# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2500");
  script_cve_id("CVE-2025-22871", "CVE-2025-4674", "CVE-2025-47906", "CVE-2025-47907");
  script_tag(name:"creation_date", value:"2025-12-11 12:41:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for golang (EulerOS-SA-2025-2500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2500");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2500");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'golang' package(s) announced via the EulerOS-SA-2025-2500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The net/http package improperly accepts a bare LF as a line terminator in chunked data chunk-size lines. This can permit request smuggling if a net/http server is used in conjunction with a server that incorrectly accepts a bare LF as part of a chunk-ext.(CVE-2025-22871)

The go command may execute unexpected commands when operating in untrusted VCS repositories. This occurs when possibly dangerous VCS configuration is present in repositories. This can happen when a repository was fetched via one VCS (e.g. Git), but contains metadata for another VCS (e.g. Mercurial). Modules which are retrieved using the go command line, i.e. via 'go get', are not affected.(CVE-2025-4674)

If the PATH environment variable contains paths which are executables (rather than just directories), passing certain strings to LookPath ('', '.', and '..'), can result in the binaries listed in the PATH being unexpectedly returned.(CVE-2025-47906)

Cancelling a query (e.g. by cancelling the context passed to one of the query methods) during a call to the Scan method of the returned Rows can result in unexpected results if other queries are being made in parallel. This can result in a race condition that may overwrite the expected results with those of another query, causing the call to Scan to return either unexpected results from the other query or an error.(CVE-2025-47907)");

  script_tag(name:"affected", value:"'golang' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

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

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.21.4~8.h115.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-devel", rpm:"golang-devel~1.21.4~8.h115.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-help", rpm:"golang-help~1.21.4~8.h115.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
