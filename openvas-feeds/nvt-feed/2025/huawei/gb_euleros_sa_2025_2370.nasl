# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2370");
  script_cve_id("CVE-2025-4138", "CVE-2025-4330", "CVE-2025-4435", "CVE-2025-4517", "CVE-2025-8194");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2025-2370)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2370");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2370");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter");
  script_xref(name:"URL", value:"https://gist.github.com/sethmlarson/1716ac5b82b73dbcbf23ad2eff8b33e1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2025-2370 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Allows the extraction filter to be ignored, allowing symlink targets to point outside the destination directory, and the modification of some file metadata.


You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of 'data' or 'tar'. See the tarfile extraction filters documentation [link moved to references] for more information.

Note that for Python 3.14 or later the default value of filter= changed from 'no filtering' to `'data', so if you are relying on this new default behavior then your usage is also affected.

Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.(CVE-2025-4330)

Allows the extraction filter to be ignored, allowing symlink targets to point outside the destination directory, and the modification of some file metadata.


You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of 'data' or 'tar'. See the tarfile extraction filters documentation [link moved to references] for more information.

Note that for Python 3.14 or later the default value of filter= changed from 'no filtering' to `'data', so if you are relying on this new default behavior then your usage is also affected.

Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.(CVE-2025-4138)

There is a defect in the CPython 'tarfile' module affecting the 'TarFile' extraction and entry enumeration APIs. The tar implementation would process tar archives with negative offsets without error, resulting in an infinite loop and deadlock during the parsing of maliciously crafted tar archives.

This vulnerability can be mitigated by including the following patch after importing the 'tarfile' module: [link moved to references](CVE-2025-8194)

Allows arbitrary filesystem writes outside the extraction directory during extraction with filter='data'. You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of 'data' or 'tar'. ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python3' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.9.9~21.h19.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fgo", rpm:"python3-fgo~3.9.9~21.h19.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unversioned-command", rpm:"python3-unversioned-command~3.9.9~21.h19.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
