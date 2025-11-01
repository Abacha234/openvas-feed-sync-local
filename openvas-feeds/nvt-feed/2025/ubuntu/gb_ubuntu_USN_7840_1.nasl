# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7840.1");
  script_cve_id("CVE-2024-35176", "CVE-2024-39908", "CVE-2024-41123", "CVE-2024-41946", "CVE-2024-47220", "CVE-2025-6442");
  script_tag(name:"creation_date", value:"2025-10-28 10:29:04 +0000 (Tue, 28 Oct 2025)");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-05 16:09:45 +0000 (Thu, 05 Sep 2024)");

  script_name("Ubuntu: Security Advisory (USN-7840-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7840-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7840-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.3, ruby2.5, ruby2.7' package(s) announced via the USN-7840-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the REXML module bunded into Ruby incorrectly
handled parsing XML documents with repeated instances of certain
characters. An attacker could possibly use this issue to cause REXML to
consume excessive resources, leading to a denial of service. Ubuntu 18.04
LTS and Ubuntu 20.04 LTS were previously addressed in USN-7256-1 and
USN-7734-1. This update addresses the issue in Ubuntu 16.04 LTS.
(CVE-2024-35176)

It was discovered that the REXML module bunded into Ruby incorrectly
handled parsing XML documents with repeated instances of certain
characters. An attacker could possibly use this issue to cause REXML to
consume excessive resources, leading to a denial of service. Ubuntu 20.04
LTS was previously addressed in USN-7256-1. This update addresses the issue
in Ubuntu 16.04 LTS and Ubuntu 18.04 LTS. (CVE-2024-39908, CVE-2024-41123)

It was discovered that the REXML module bunded into Ruby incorrectly
handled parsing XML documents with many entity expansions. An attacker
could possibly use this issue to cause REXML to consume excessive
resources, leading to a denial of service. Ubuntu 20.04 LTS was previously
addressed in USN-7091-2. This update addresses the issue in Ubuntu 16.04
LTS and Ubuntu 18.04 LTS. (CVE-2024-41946)

It was discovered that the WEBrick module bundled into Ruby incorrectly
handled having both a Content-Length header and a Transfer-Encoding header.
A remote attacker could possibly use this issue to perform a HTTP request
smuggling attack. (CVE-2024-47220)

It was discovered that the WEBrick module bundled into Ruby incorrectly
parsed HTTP headers. In configurations where the WEBrick module is placed
behind an HTTP proxy, a remote attacker could possibly use this issue to
perform an HTTP Request Smuggling attack. (CVE-2025-6442)");

  script_tag(name:"affected", value:"'ruby2.3, ruby2.5, ruby2.7' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.1-2~ubuntu16.04.16+esm11", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.1-2~ubuntu16.04.16+esm11", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.5", ver:"2.5.1-1ubuntu1.16+esm6", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ruby2.5", ver:"2.5.1-1ubuntu1.16+esm6", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libruby2.7", ver:"2.7.0-5ubuntu1.18+esm3", rls:"UBUNTU20.04 LTS"))) {
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
