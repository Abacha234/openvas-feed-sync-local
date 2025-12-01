# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7875.1");
  script_cve_id("CVE-2023-52477", "CVE-2023-52574", "CVE-2023-52650", "CVE-2024-27074", "CVE-2024-35849", "CVE-2024-41006", "CVE-2024-47685", "CVE-2024-49924", "CVE-2024-50006", "CVE-2024-50051", "CVE-2024-50202", "CVE-2024-50299", "CVE-2024-53124", "CVE-2024-53130", "CVE-2024-53131", "CVE-2024-53150", "CVE-2024-56767", "CVE-2024-57996", "CVE-2025-21796", "CVE-2025-37752", "CVE-2025-37785", "CVE-2025-37838", "CVE-2025-38350", "CVE-2025-38352", "CVE-2025-38477", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-40300");
  script_tag(name:"creation_date", value:"2025-11-21 04:05:43 +0000 (Fri, 21 Nov 2025)");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-23 15:19:06 +0000 (Wed, 23 Oct 2024)");

  script_name("Ubuntu: Security Advisory (USN-7875-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7875-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7875-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oracle' package(s) announced via the USN-7875-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jean-Claude Graf, Sandro Ruegge, Ali Hajiabadi, and Kaveh Razavi discovered
that the Linux kernel contained insufficient branch predictor isolation
between a guest and a userspace hypervisor for certain processors. This
flaw is known as VMSCAPE. An attacker in a guest VM could possibly use this
to expose sensitive information from the host OS. (CVE-2025-40300)

Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - DMA engine subsystem,
 - GPU drivers,
 - HSI subsystem,
 - Media drivers,
 - Ethernet team driver,
 - SPI subsystem,
 - USB core drivers,
 - Framebuffer layer,
 - BTRFS file system,
 - Ext4 file system,
 - Network file system (NFS) server daemon,
 - NILFS2 file system,
 - Timer subsystem,
 - DCCP (Datagram Congestion Control Protocol),
 - IPv6 networking,
 - NET/ROM layer,
 - Packet sockets,
 - Network traffic control,
 - SCTP protocol,
 - VMware vSockets driver,
 - USB sound devices,
(CVE-2023-52477, CVE-2023-52574, CVE-2023-52650, CVE-2024-27074,
CVE-2024-35849, CVE-2024-41006, CVE-2024-47685, CVE-2024-49924,
CVE-2024-50006, CVE-2024-50051, CVE-2024-50202, CVE-2024-50299,
CVE-2024-53124, CVE-2024-53130, CVE-2024-53131, CVE-2024-53150,
CVE-2024-56767, CVE-2024-57996, CVE-2025-21796, CVE-2025-37752,
CVE-2025-37785, CVE-2025-37838, CVE-2025-38350, CVE-2025-38352,
CVE-2025-38477, CVE-2025-38617, CVE-2025-38618)");

  script_tag(name:"affected", value:"'linux-oracle' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.15.0-1148-oracle", ver:"4.15.0-1148.159~16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"4.15.0.1148.159~16.04.1", rls:"UBUNTU16.04 LTS"))) {
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
