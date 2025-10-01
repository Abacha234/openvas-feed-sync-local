# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7280.3");
  script_cve_id("CVE-2024-11168", "CVE-2025-0938");
  script_tag(name:"creation_date", value:"2025-09-30 04:04:44 +0000 (Tue, 30 Sep 2025)");
  script_version("2025-09-30T05:39:19+0000");
  script_tag(name:"last_modification", value:"2025-09-30 05:39:19 +0000 (Tue, 30 Sep 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7280-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7280-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7280-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2125702");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7' package(s) announced via the USN-7280-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7280-2 fixed vulnerabilities in Python. It was discovered that the
fixes for CVE-2025-0938 and CVE-2024-11168 were incorrectly applied on
Ubuntu 14.04 LTS as a result. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that Python incorrectly handled parsing domain names that
 included square brackets. A remote attacker could possibly use this issue
 to perform a Server-Side Request Forgery (SSRF) attack.");

  script_tag(name:"affected", value:"'python2.7' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.6-8ubuntu0.6+esm28", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.6+esm28", rls:"UBUNTU14.04 LTS"))) {
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
