# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2026.7942.1");
  script_cve_id("CVE-2025-13601", "CVE-2025-14087", "CVE-2025-3360", "CVE-2025-6052", "CVE-2025-7039");
  script_tag(name:"creation_date", value:"2026-01-08 04:18:30 +0000 (Thu, 08 Jan 2026)");
  script_version("2026-01-08T05:48:01+0000");
  script_tag(name:"last_modification", value:"2026-01-08 05:48:01 +0000 (Thu, 08 Jan 2026)");
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 15:15:51 +0000 (Wed, 26 Nov 2025)");

  script_name("Ubuntu: Security Advisory (USN-7942-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS|25\.04|25\.10)");

  script_xref(name:"Advisory-ID", value:"USN-7942-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7942-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glib2.0' package(s) announced via the USN-7942-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that GLib incorrectly handled escaping URI strings. An
attacker could use this issue to cause GLib to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2025-13601)

It was discovered that GLib incorrectly parsed certain GVariants. An
attacker could use this issue to cause GLib to crash, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2025-14087)

It was discovered that GLib incorrectly parsed certain long invalid ISO
8601 timestamps. An attacker could possibly use this issue to cause GLib to
crash, resulting in a denial of service. This issue only affected Ubuntu
22.04 LTS and Ubuntu 24.04 LTS. (CVE-2025-3360)

It was discovered that GLib incorrectly handled GString memory operations.
An attacker could use this issue to cause GLib to crash, resulting in a
denial of service, or possibly execute arbitrary code. This issue only
affected Ubuntu 24.04 LTS and Ubuntu 25.04. (CVE-2025-6052)

It was discovered that GLib incorrectly handled creating temporary files.
An attacker could possibly use this issue to access unauthorized data. This
issue only affected Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 25.04.
(CVE-2025-7039)");

  script_tag(name:"affected", value:"'glib2.0' package(s) on Ubuntu 22.04, Ubuntu 24.04, Ubuntu 25.04, Ubuntu 25.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0", ver:"2.72.4-0ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.72.4-0ubuntu2.7", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0t64", ver:"2.80.0-6ubuntu3.6", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.80.0-6ubuntu3.6", rls:"UBUNTU24.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0t64", ver:"2.84.1-1ubuntu0.2", rls:"UBUNTU25.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.84.1-1ubuntu0.2", rls:"UBUNTU25.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-0t64", ver:"2.86.0-2ubuntu0.1", rls:"UBUNTU25.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libglib2.0-bin", ver:"2.86.0-2ubuntu0.1", rls:"UBUNTU25.10"))) {
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
