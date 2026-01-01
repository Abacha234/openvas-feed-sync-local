# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2025.7922.3");
  script_cve_id("CVE-2022-49026", "CVE-2022-49390", "CVE-2024-47691", "CVE-2024-49935", "CVE-2024-50067", "CVE-2024-50095", "CVE-2024-50196", "CVE-2024-53090", "CVE-2024-53218", "CVE-2025-21855", "CVE-2025-37958", "CVE-2025-38666", "CVE-2025-39964", "CVE-2025-39993", "CVE-2025-40018");
  script_tag(name:"creation_date", value:"2025-12-22 04:19:31 +0000 (Mon, 22 Dec 2025)");
  script_version("2025-12-23T05:46:52+0000");
  script_tag(name:"last_modification", value:"2025-12-23 05:46:52 +0000 (Tue, 23 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-13 21:18:17 +0000 (Thu, 13 Mar 2025)");

  script_name("Ubuntu: Security Advisory (USN-7922-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7922-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7922-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-oracle-5.4' package(s) announced via the USN-7922-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues were discovered in the Linux kernel.
An attacker could possibly use these to compromise the system.
This update corrects flaws in the following subsystems:
 - Cryptographic API,
 - ACPI drivers,
 - InfiniBand drivers,
 - Media drivers,
 - Network drivers,
 - Pin controllers subsystem,
 - AFS file system,
 - F2FS file system,
 - Tracing infrastructure,
 - Memory management,
 - Appletalk network protocol,
 - Netfilter,
(CVE-2022-49026, CVE-2022-49390, CVE-2024-47691, CVE-2024-49935,
CVE-2024-50067, CVE-2024-50095, CVE-2024-50196, CVE-2024-53090,
CVE-2024-53218, CVE-2025-21855, CVE-2025-37958, CVE-2025-38666,
CVE-2025-39964, CVE-2025-39993, CVE-2025-40018)");

  script_tag(name:"affected", value:"'linux-oracle-5.4' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1151-oracle", ver:"5.4.0-1151.161~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle", ver:"5.4.0.1151.161~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-oracle-5.4", ver:"5.4.0.1151.161~18.04.1", rls:"UBUNTU18.04 LTS"))) {
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
