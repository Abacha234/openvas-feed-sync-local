# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7912.1");
  script_cve_id("CVE-2025-58436");
  script_tag(name:"creation_date", value:"2025-12-08 04:13:11 +0000 (Mon, 08 Dec 2025)");
  script_version("2025-12-08T05:46:14+0000");
  script_tag(name:"last_modification", value:"2025-12-08 05:46:14 +0000 (Mon, 08 Dec 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-04 17:24:12 +0000 (Thu, 04 Dec 2025)");

  script_name("Ubuntu: Security Advisory (USN-7912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7912-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7912-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2133207");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-7912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Johannes Meixner and Paul Zirnik discovered that CUPS incorrectly handled
clients that send messages slowly. A remote attacker could possibly use
this issue to cause CUPS to stop responding, resulting in a denial of
service. (CVE-2025-58436)

In addition, this update fixes a regression introduced in USN-7897-1 which
resulted in certain invalid configuration file directives to cause the CUPS
daemon to fail to start.");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.4.1op1-1ubuntu4.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.4.1op1-1ubuntu4.16", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.4.7-1.2ubuntu7.9", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.4.7-1.2ubuntu7.9", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU25.04") {

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.4.12-0ubuntu1.6", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.4.12-0ubuntu1.6", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cups", ver:"2.4.12-0ubuntu3.5", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cups-daemon", ver:"2.4.12-0ubuntu3.5", rls:"UBUNTU25.10"))) {
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
