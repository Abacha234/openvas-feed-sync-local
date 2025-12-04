# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2025.6068");
  script_cve_id("CVE-2024-28956", "CVE-2024-36350", "CVE-2024-36357", "CVE-2025-27465", "CVE-2025-27466", "CVE-2025-58142", "CVE-2025-58143", "CVE-2025-58144", "CVE-2025-58145", "CVE-2025-58147", "CVE-2025-58148", "CVE-2025-58149");
  script_tag(name:"creation_date", value:"2025-12-03 04:10:40 +0000 (Wed, 03 Dec 2025)");
  script_version("2025-12-03T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-12-03 05:40:19 +0000 (Wed, 03 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-6068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(12|13)");

  script_xref(name:"Advisory-ID", value:"DSA-6068-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2025/DSA-6068-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-6068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 12, Debian 13.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxencall1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxendevicemodel1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenevtchn1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenforeignmemory1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxengnttab1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenhypfs1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenmisc4.17", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore4", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoolcore1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoollog1", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-doc", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.17-amd64", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.17-amd64-dbg", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.17-arm64", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.17-arm64-dbg", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.17-armhf", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.17-armhf-dbg", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-common", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-armhf", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.17", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.17-dbg", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.17.5+72-g01140da4e8-1", rls:"DEB12"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB13") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxencall1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxendevicemodel1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenevtchn1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenforeignmemory1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxengnttab1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenhypfs1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenmisc4.20", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore4", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoolcore1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxentoollog1", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-doc", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.20-amd64", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.20-amd64-dbg", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.20-arm64", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.20-arm64-dbg", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-common", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-arm64", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.20", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.20-dbg", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.20.2+7-g1badcf5035-0+deb13u1", rls:"DEB13"))) {
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
