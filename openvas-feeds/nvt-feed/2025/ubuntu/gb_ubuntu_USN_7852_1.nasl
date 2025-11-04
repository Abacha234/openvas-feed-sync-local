# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7852.1");
  script_cve_id("CVE-2025-7425");
  script_tag(name:"creation_date", value:"2025-11-03 04:09:45 +0000 (Mon, 03 Nov 2025)");
  script_version("2025-11-03T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-11-03 05:40:08 +0000 (Mon, 03 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-10 14:15:27 +0000 (Thu, 10 Jul 2025)");

  script_name("Ubuntu: Security Advisory (USN-7852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04)");

  script_xref(name:"Advisory-ID", value:"USN-7852-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7852-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the USN-7852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libxslt, used by libxml2, incorrectly handled
certain attributes. An attacker could use this issue to cause a crash,
resulting in a denial of service, or possibly execute arbitrary code. This
update adds a fix to libxml2 to mitigate the libxslt vulnerability.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.13+dfsg-1ubuntu0.10", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2", ver:"2.9.13+dfsg-1ubuntu0.10", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.9.14+dfsg-1.3ubuntu3.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2", ver:"2.9.14+dfsg-1.3ubuntu3.6", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libxml2", ver:"2.12.7+dfsg+really2.9.14-0.4ubuntu0.4", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-libxml2", ver:"2.12.7+dfsg+really2.9.14-0.4ubuntu0.4", rls:"UBUNTU25.04"))) {
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
