# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2025.4423");
  script_cve_id("CVE-2023-23082", "CVE-2023-30207");
  script_tag(name:"creation_date", value:"2025-12-29 04:24:20 +0000 (Mon, 29 Dec 2025)");
  script_version("2026-01-01T05:49:19+0000");
  script_tag(name:"last_modification", value:"2026-01-01 05:49:19 +0000 (Thu, 01 Jan 2026)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 12:36:44 +0000 (Wed, 12 Jul 2023)");

  script_name("Debian: Security Advisory (DLA-4423-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DLA-4423-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2025/DLA-4423-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kodi' package(s) announced via the DLA-4423-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'kodi' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kodi", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-addons-dev", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-addons-dev-common", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-bin", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-data", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-eventclients-common", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-eventclients-dev", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-eventclients-kodi-send", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-eventclients-ps3", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-eventclients-wiiremote", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-eventclients-zeroconf", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kodi-repository-kodi", ver:"2:19.1+dfsg2-2+deb11u2", rls:"DEB11"))) {
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
