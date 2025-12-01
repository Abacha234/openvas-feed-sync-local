# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7891.1");
  script_cve_id("CVE-2023-53159", "CVE-2025-24898", "CVE-2025-3416");
  script_tag(name:"creation_date", value:"2025-11-28 04:06:10 +0000 (Fri, 28 Nov 2025)");
  script_version("2025-11-28T05:40:45+0000");
  script_tag(name:"last_modification", value:"2025-11-28 05:40:45 +0000 (Fri, 28 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-07 15:30:41 +0000 (Thu, 07 Aug 2025)");

  script_name("Ubuntu: Security Advisory (USN-7891-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7891-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7891-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-openssl' package(s) announced via the USN-7891-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matt Mastracci discovered that rust-openssl was incorrectly handling server
lifetimes in certain functions. An attacker could possibly use this issue
to cause a denial of service or run arbitrary memory content to the client.
(CVE-2025-24898)

It was discovered that rust-openssl was incorrectly handling empty strings
when setting the host in certain functions. An attacker could possibly use
this issue to cause a denial of service. This issue only affected
Ubuntu 20.04 LTS and Ubuntu 22.04 LTS. (CVE-2023-53159)

It was discovered that rust-openssl was incorrectly handling property
arguments in certain functions. An attacker could possibly use this
issue to cause a denial of service. This issue only affected
Ubuntu 24.04 LTS. (CVE-2025-3416)");

  script_tag(name:"affected", value:"'rust-openssl' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 24.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"librust-openssl-dev", ver:"0.10.23-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"librust-openssl-dev", ver:"0.10.36-1ubuntu0.1~esm1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"librust-openssl-dev", ver:"0.10.57-1ubuntu0.1~esm1", rls:"UBUNTU24.04 LTS"))) {
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
