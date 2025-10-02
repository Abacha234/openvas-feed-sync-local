# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4315");
  script_cve_id("CVE-2024-13978", "CVE-2025-9900");
  script_tag(name:"creation_date", value:"2025-09-30 14:31:19 +0000 (Tue, 30 Sep 2025)");
  script_version("2025-10-01T05:39:08+0000");
  script_tag(name:"last_modification", value:"2025-10-01 05:39:08 +0000 (Wed, 01 Oct 2025)");
  script_tag(name:"cvss_base", value:"1.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-09-23 17:15:38 +0000 (Tue, 23 Sep 2025)");

  script_name("Debian: Security Advisory (DLA-4315-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4315-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4315-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DLA-4315-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-dev", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-doc", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-opengl", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff-tools", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiff5-dev", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtiffxx5", ver:"4.2.0-1+deb11u7", rls:"DEB11"))) {
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
