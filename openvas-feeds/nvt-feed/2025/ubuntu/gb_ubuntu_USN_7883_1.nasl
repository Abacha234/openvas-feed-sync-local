# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7883.1");
  script_cve_id("CVE-2025-53057", "CVE-2025-53066");
  script_tag(name:"creation_date", value:"2025-11-26 10:57:50 +0000 (Wed, 26 Nov 2025)");
  script_version("2025-11-27T05:40:40+0000");
  script_tag(name:"last_modification", value:"2025-11-27 05:40:40 +0000 (Thu, 27 Nov 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-21 20:20:47 +0000 (Tue, 21 Oct 2025)");

  script_name("Ubuntu: Security Advisory (USN-7883-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7883-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7883-1");
  script_xref(name:"URL", value:"https://openjdk.org/groups/vulnerability/advisories/2025-10-21");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-17' package(s) announced via the USN-7883-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jinfeng Guo discovered that the Security component of OpenJDK 17 did not
correctly handle certain representations of encoded strings. An
unauthenticated remote attacker could possibly use this issue to modify
files or leak sensitive information. (CVE-2025-53057)

Darius Bohni discovered that the JAXP component of OpenJDK 17 was
vulnerable to a XML External Entity (XEE) attack. An unauthenticated
remote attacker could possibly use this issue to modify files or leak
sensitive information. (CVE-2025-53066)

In addition to security fixes, the updated packages contain bug fixes, new
features, and possibly incompatible changes.

Please see the following for more information:
[link moved to references]");

  script_tag(name:"affected", value:"'openjdk-17' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.17+10-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.17+10-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.17+10-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.17+10-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.17+10-1~18.04", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.17+10-1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.17+10-1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.17+10-1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.17+10-1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.17+10-1~20.04", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.17+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.17+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.17+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.17+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.17+10-1~22.04", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.17+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.17+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.17+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.17+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.17+10-1~24.04", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.17+10-1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.17+10-1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.17+10-1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.17+10-1~25.04", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.17+10-1~25.04", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk", ver:"17.0.17+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jdk-headless", ver:"17.0.17+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre", ver:"17.0.17+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-headless", ver:"17.0.17+10-1~25.10", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openjdk-17-jre-zero", ver:"17.0.17+10-1~25.10", rls:"UBUNTU25.10"))) {
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
