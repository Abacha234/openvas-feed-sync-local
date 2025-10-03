# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7788.1");
  script_cve_id("CVE-2015-4467", "CVE-2015-4468", "CVE-2015-4469", "CVE-2015-4472", "CVE-2017-11423", "CVE-2017-6419", "CVE-2018-14679", "CVE-2018-14680", "CVE-2018-14681", "CVE-2018-14682", "CVE-2018-18585", "CVE-2019-1010305");
  script_tag(name:"creation_date", value:"2025-10-02 04:04:33 +0000 (Thu, 02 Oct 2025)");
  script_version("2025-10-02T05:38:29+0000");
  script_tag(name:"last_modification", value:"2025-10-02 05:38:29 +0000 (Thu, 02 Oct 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-03 15:37:26 +0000 (Wed, 03 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-7788-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7788-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7788-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libmspack' package(s) announced via the USN-7788-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered that libmspack did not correctly handle certain
integer operations and bounds checking. A remote attacker could possibly
use this issue to cause a denial of service. (CVE-2015-4467, CVE-2015-4468,
CVE-2015-4469, CVE-2015-4472)

It was discovered that libmspack incorrectly handled certain malformed CAB
files. A remote attacker could use this issue to cause libmspack to crash,
resulting in a denial of service. (CVE-2017-11423)

It was discovered that libmspack incorrectly handled certain malformed CHM
files. A remote attacker could use this issue to cause libmspack to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2017-6419)

Hanno Bock discovered that libmspack incorrectly handled certain CHM files.
An attacker could possibly use this issue to cause a denial of service.
(CVE-2018-14679, CVE-2018-14680)

Jakub Wilk discovered that libmspack incorrectly handled certain KWAJ
files. An attacker could possibly use this issue to execute arbitrary code.
(CVE-2018-14681)

Dmitry Glavatskikh discovered that libmspack incorrectly handled certain
CHM files. An attacker could possibly use this issue to execute arbitrary
code. (CVE-2018-14682)

It was discovered libmspack incorrectly handled certain malformed CAB
files. A remote attacker could use this issue to cause libmspack to crash,
resulting in a denial of service. (CVE-2018-18585)

It was discovered that libmspack incorrectly handled certain CHM files. A
remote attacker could possibly use this issue to access sensitive
information. (CVE-2019-1010305)");

  script_tag(name:"affected", value:"'libmspack' package(s) on Ubuntu 14.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmspack-dev", ver:"0.4-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmspack-doc", ver:"0.4-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmspack0", ver:"0.4-1ubuntu0.1~esm2", rls:"UBUNTU14.04 LTS"))) {
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
