# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7825.1");
  script_cve_id("CVE-2018-1000036", "CVE-2018-10289", "CVE-2018-16647", "CVE-2018-16648", "CVE-2020-21896", "CVE-2020-26683", "CVE-2021-3407", "CVE-2021-37220");
  script_tag(name:"creation_date", value:"2025-10-17 04:05:08 +0000 (Fri, 17 Oct 2025)");
  script_version("2025-10-29T05:40:29+0000");
  script_tag(name:"last_modification", value:"2025-10-29 05:40:29 +0000 (Wed, 29 Oct 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-31 00:36:14 +0000 (Sat, 31 Jul 2021)");

  script_name("Ubuntu: Security Advisory (USN-7825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7825-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7825-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mupdf' package(s) announced via the USN-7825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that MuPDF incorrectly managed memory, resulting in a
memory leak. An attacker could possibly use this issue to cause a denial
of service. This issue only affected Ubuntu 18.04 LTS. (CVE-2018-1000036)

It was discovered that MuPDF could enter an infinite loop when parsing
certain PDF files. An attacker could possibly use this issue to cause a
denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-10289)

It was discovered that MuPDF incorrectly managed memory, possibly leading
to a segmentation fault. An attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 18.04 LTS.
(CVE-2018-16647, CVE-2018-16648)

It was discovered that MuPDF contained a use-after-free vulnerability.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2020-21896)

It was discovered that MuPDF incorrectly managed memory, resulting in a
memory leak. An attacker could possibly use this issue to cause a denial
of service or obtain sensitive information. This issue only affected
Ubuntu 20.04 LTS. (CVE-2020-26683)

Maxim Mishechkin, Vitalii Akolzin, Shamil Kurmangaleev, Denis Straghkov,
Fedor Nis'kov and Ivan Gulakov discovered that MuPDF incorrectly managed
memory under certain circumstances, leading to a double-free. An attacker
could possibly use this to cause a denial of service. This issue only
affected Ubuntu 16.04 LTS, Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2021-3407)

Xuwei Liu discovered that MuPDF may perform an out-of-bounds write under
certain circumstances. An attacker could possibly use this issue to cause
a denial of service. This issue only affected Ubuntu 18.04 LTS and Ubuntu
20.04 LTS. (CVE-2021-37220)");

  script_tag(name:"affected", value:"'mupdf' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.7a-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.7a-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.7a-1ubuntu0.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.12.0+ds1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.12.0+ds1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.12.0+ds1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.16.1+ds1-1ubuntu1+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.16.1+ds1-1ubuntu1+esm1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.16.1+ds1-1ubuntu1+esm1", rls:"UBUNTU20.04 LTS"))) {
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
