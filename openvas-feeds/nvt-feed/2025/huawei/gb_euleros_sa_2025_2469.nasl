# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2469");
  script_cve_id("CVE-2025-1795", "CVE-2025-4516", "CVE-2025-6069", "CVE-2025-8194");
  script_tag(name:"creation_date", value:"2025-12-11 12:41:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2025-2469)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2469");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2469");
  script_xref(name:"URL", value:"https://gist.github.com/sethmlarson/1716ac5b82b73dbcbf23ad2eff8b33e1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2025-2469 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"During an address list folding when a separating comma ends up on a folded line and that line is to be unicode-encoded then the separator itself is also unicode-encoded. Expected behavior is that the separating comma remains a plan comma. This can result in the address header being misinterpreted by some mail servers.(CVE-2025-1795)

There is an issue in CPython when using `bytes.decode('unicode_escape', error='ignore<pipe>replace')`. If you are not using the 'unicode_escape' encoding or an error handler your usage is not affected. To work-around this issue you may stop using the error= handler and instead wrap the bytes.decode() call in a try-except catching the DecodeError.(CVE-2025-4516)

The html.parser.HTMLParser class had worse-case quadratic complexity when processing certain crafted malformed inputs potentially leading to amplified denial-of-service.(CVE-2025-6069)

There is a defect in the CPython 'tarfile' module affecting the 'TarFile' extraction and entry enumeration APIs. The tar implementation would process tar archives with negative offsets without error, resulting in an infinite loop and deadlock during the parsing of maliciously crafted tar archives.

This vulnerability can be mitigated by including the following patch after importing the 'tarfile' module: [link moved to references](CVE-2025-8194)");

  script_tag(name:"affected", value:"'python3' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.9.9~7.h36.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unversioned-command", rpm:"python3-unversioned-command~3.9.9~7.h36.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
