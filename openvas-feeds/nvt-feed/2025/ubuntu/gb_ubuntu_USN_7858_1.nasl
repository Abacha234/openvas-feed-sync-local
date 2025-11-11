# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7858.1");
  script_cve_id("CVE-2025-52885");
  script_tag(name:"creation_date", value:"2025-11-10 04:09:39 +0000 (Mon, 10 Nov 2025)");
  script_version("2025-11-10T05:40:50+0000");
  script_tag(name:"last_modification", value:"2025-11-10 05:40:50 +0000 (Mon, 10 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7858-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7858-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7858-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the USN-7858-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that poppler incorrectly handled certain PDF files.
An attacker could possibly use this issue to cause a crash.");

  script_tag(name:"affected", value:"'poppler' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler97", ver:"0.86.1-0ubuntu1.7+esm3", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"0.86.1-0ubuntu1.7+esm3", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler118", ver:"22.02.0-2ubuntu0.12", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"22.02.0-2ubuntu0.12", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler134", ver:"24.02.0-1ubuntu9.8", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"24.02.0-1ubuntu9.8", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler147", ver:"25.03.0-3ubuntu1.4", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"25.03.0-3ubuntu1.4", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpoppler147", ver:"25.03.0-10ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"poppler-utils", ver:"25.03.0-10ubuntu0.1", rls:"UBUNTU25.10"))) {
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
