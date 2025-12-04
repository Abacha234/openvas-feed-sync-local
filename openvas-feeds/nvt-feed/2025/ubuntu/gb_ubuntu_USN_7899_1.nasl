# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7899.1");
  script_cve_id("CVE-2025-0840", "CVE-2025-1153", "CVE-2025-1181", "CVE-2025-1182", "CVE-2025-11839", "CVE-2025-11840", "CVE-2025-3198", "CVE-2025-5244", "CVE-2025-5245", "CVE-2025-7545", "CVE-2025-8225");
  script_tag(name:"creation_date", value:"2025-12-02 09:12:31 +0000 (Tue, 02 Dec 2025)");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-30 15:59:48 +0000 (Wed, 30 Jul 2025)");

  script_name("Ubuntu: Security Advisory (USN-7899-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7899-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7899-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'binutils' package(s) announced via the USN-7899-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GNU binutils could be forced to perform an out-
of-bounds read in certain instances. An attacker with local access to
a system could possibly use this issue to cause a denial of service.
(CVE-2025-11839, CVE-2025-11840)

It was discovered that GNU binutils incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04
LTS, and Ubuntu 20.04 LTS. (CVE-2025-8225)

It was discovered that GNU binutils incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a crash or
execute arbitrary code. This issue only affected Ubuntu 14.04 LTS,
Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS.
(CVE-2025-5244, CVE-2025-5245)

It was discovered that GNU binutils incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2025-3198)

It was discovered that GNU binutils incorrectly handled certain files.
An attacker could possibly use this issue to cause a crash. This issue
only affected Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, and Ubuntu 18.04 LTS.
(CVE-2025-1182)

It was discovered that ld in GNU binutils incorrectly handled certain
files. An attacker could possibly use this issue to cause a crash,
expose sensitive information or execute arbitrary code. This issue
only affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS.
(CVE-2025-1181)

It was discovered that GNU binutils incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a crash, expose
sensitive information or execute arbitrary code. This issue only
affected Ubuntu 25.04. (CVE-2025-1153)

It was discovered that GNU binutils incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a crash or execute
arbitrary code. This issue only affected Ubuntu 14.04 LTS.
(CVE-2025-0840)");

  script_tag(name:"affected", value:"'binutils' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.24-5ubuntu14.2+esm7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.24-5ubuntu14.2+esm7", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.26.1-1ubuntu1~16.04.8+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.26.1-1ubuntu1~16.04.8+esm13", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.30-21ubuntu1~18.04.9+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.30-21ubuntu1~18.04.9+esm5", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.34-6ubuntu1.11+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.34-6ubuntu1.11+esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.38-4ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.38-4ubuntu2.11", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.42-4ubuntu2.7", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.42-4ubuntu2.7", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.44-3ubuntu1.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.44-3ubuntu1.2", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"binutils", ver:"2.45-7ubuntu1.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"binutils-multiarch", ver:"2.45-7ubuntu1.1", rls:"UBUNTU25.10"))) {
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
