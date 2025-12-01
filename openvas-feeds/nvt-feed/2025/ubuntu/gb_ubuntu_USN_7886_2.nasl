# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7886.2");
  script_cve_id("CVE-2025-6075", "CVE-2025-8291");
  script_tag(name:"creation_date", value:"2025-11-28 04:06:10 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7886-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7886-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7886-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.13' package(s) announced via the USN-7886-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7886-1 fixed vulnerabilities in Python. This update provides the
corresponding updates for python3.13 in Ubuntu 25.04 and Ubuntu 25.10.

Original advisory details:

 It was discovered that Python inefficiently handled expanding system
 environment variables. An attacker could possibly use this issue to cause
 Python to consume excessive resources, leading to a denial of service.
 (CVE-2025-6075)

 Caleb Brown discovered that Python incorrectly handled the ZIP64 End of
 Central Directory (EOCD) Locator record offset value. An attacker could
 possibly use this issue to obfuscate malicious content. (CVE-2025-8291)");

  script_tag(name:"affected", value:"'python3.13' package(s) on Ubuntu 25.04, Ubuntu 25.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.13", ver:"3.13.3-1ubuntu0.4", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.13", ver:"3.13.3-1ubuntu0.4", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libpython3.13", ver:"3.13.7-1ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.13", ver:"3.13.7-1ubuntu0.1", rls:"UBUNTU25.10"))) {
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
