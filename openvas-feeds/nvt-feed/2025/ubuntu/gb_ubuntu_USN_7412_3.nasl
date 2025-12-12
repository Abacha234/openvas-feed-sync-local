# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7412.3");
  script_cve_id("CVE-2025-30258");
  script_tag(name:"creation_date", value:"2025-12-10 10:11:02 +0000 (Wed, 10 Dec 2025)");
  script_version("2025-12-11T05:46:19+0000");
  script_tag(name:"last_modification", value:"2025-12-11 05:46:19 +0000 (Thu, 11 Dec 2025)");
  script_tag(name:"cvss_base", value:"3.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-10 14:29:32 +0000 (Fri, 10 Oct 2025)");

  script_name("Ubuntu: Security Advisory (USN-7412-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7412-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7412-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg2' package(s) announced via the USN-7412-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7412-1 fixed a vulnerability in GnuPG. This update provides the
corresponding update for Ubuntu 16.04 LTS and Ubuntu 18.04 LTS.

Original advisory details:

 It was discovered that GnuPG incorrectly handled importing keys with
 certain crafted subkey data. If a user or automated system were tricked
 into importing a specially crafted key, a remote attacker may prevent
 users from importing other keys in the future.");

  script_tag(name:"affected", value:"'gnupg2' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"2.1.11-6ubuntu2.1+esm2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpgv2", ver:"2.1.11-6ubuntu2.1+esm2", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gnupg", ver:"2.2.4-1ubuntu1.6+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnupg2", ver:"2.2.4-1ubuntu1.6+esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gpg", ver:"2.2.4-1ubuntu1.6+esm1", rls:"UBUNTU18.04 LTS"))) {
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
