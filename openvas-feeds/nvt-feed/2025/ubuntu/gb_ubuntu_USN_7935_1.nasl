# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7935.1");
  script_cve_id("CVE-2025-21729", "CVE-2025-37838", "CVE-2025-37958", "CVE-2025-38118", "CVE-2025-38227", "CVE-2025-38352", "CVE-2025-38616", "CVE-2025-38666", "CVE-2025-38678", "CVE-2025-39964", "CVE-2025-39993", "CVE-2025-40018", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-12-16 16:35:37 +0000 (Tue, 16 Dec 2025)");
  script_version("2025-12-19T05:45:49+0000");
  script_tag(name:"last_modification", value:"2025-12-19 05:45:49 +0000 (Fri, 19 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-18 19:38:30 +0000 (Thu, 18 Dec 2025)");

  script_name("Ubuntu: Security Advisory (USN-7935-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|24\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-7935-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7935-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-azure, linux-azure-6.8' package(s) announced via the USN-7935-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jean-Claude Graf, Sandro Ruegge, Ali Hajiabadi, and Kaveh Razavi discovered
that the Linux kernel contained insufficient branch predictor isolation
between a guest and a userspace hypervisor for certain processors. This
flaw is known as VMSCAPE. An attacker in a guest VM could possibly use this
to expose sensitive information from the host OS. (CVE-2025-40300)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Cryptographic API,
 - HSI subsystem,
 - Media drivers,
 - Network drivers,
 - Bluetooth subsystem,
 - Timer subsystem,
 - Memory management,
 - Appletalk network protocol,
 - Netfilter,
 - TLS protocol,
(CVE-2025-21729, CVE-2025-37838, CVE-2025-37958, CVE-2025-38118,
CVE-2025-38227, CVE-2025-38352, CVE-2025-38616, CVE-2025-38666,
CVE-2025-38678, CVE-2025-39964, CVE-2025-39993, CVE-2025-40018)");

  script_tag(name:"affected", value:"'linux-azure, linux-azure-6.8' package(s) on Ubuntu 22.04, Ubuntu 24.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1044-azure", ver:"6.8.0-1044.50~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure", ver:"6.8.0-1044.50~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-6.8", ver:"6.8.0-1044.50~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1044-azure", ver:"6.8.0-1044.50", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-6.8", ver:"6.8.0-1044.50", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-azure-lts-24.04", ver:"6.8.0-1044.50", rls:"UBUNTU24.04 LTS"))) {
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
