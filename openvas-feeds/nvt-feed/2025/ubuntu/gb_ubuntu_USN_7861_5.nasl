# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7861.5");
  script_cve_id("CVE-2025-37838", "CVE-2025-38118", "CVE-2025-38352", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-12-04 09:07:07 +0000 (Thu, 04 Dec 2025)");
  script_version("2025-12-05T05:44:55+0000");
  script_tag(name:"last_modification", value:"2025-12-05 05:44:55 +0000 (Fri, 05 Dec 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7861-5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU24\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7861-5");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7861-5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-raspi, linux-raspi-realtime, linux-xilinx' package(s) announced via the USN-7861-5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jean-Claude Graf, Sandro Ruegge, Ali Hajiabadi, and Kaveh Razavi discovered
that the Linux kernel contained insufficient branch predictor isolation
between a guest and a userspace hypervisor for certain processors. This
flaw is known as VMSCAPE. An attacker in a guest VM could possibly use this
to expose sensitive information from the host OS. (CVE-2025-40300)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - HSI subsystem,
 - Bluetooth subsystem,
 - Timer subsystem,
(CVE-2025-37838, CVE-2025-38118, CVE-2025-38352)");

  script_tag(name:"affected", value:"'linux-raspi, linux-raspi-realtime, linux-xilinx' package(s) on Ubuntu 24.04.");

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

if(release == "UBUNTU24.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1019-xilinx", ver:"6.8.0-1019.20", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-1042-raspi", ver:"6.8.0-1042.46", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-6.8.0-2033-raspi-realtime", ver:"6.8.0-2033.34", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi", ver:"6.8.0-1042.46", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-6.8", ver:"6.8.0-1042.46", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-realtime", ver:"6.8.0-2033.34", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-raspi-realtime-6.8", ver:"6.8.0-2033.34", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx", ver:"6.8.0.1019.20", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-6.8", ver:"6.8.0.1019.20", rls:"UBUNTU24.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-xilinx-zynqmp", ver:"6.8.0.1019.20", rls:"UBUNTU24.04 LTS"))) {
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
