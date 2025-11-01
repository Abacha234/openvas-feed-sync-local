# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844930");
  script_cve_id("CVE-2021-20292", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-28038", "CVE-2021-28688", "CVE-2021-29264", "CVE-2021-29265", "CVE-2021-29650", "CVE-2021-30002");
  script_tag(name:"creation_date", value:"2021-05-12 03:01:03 +0000 (Wed, 12 May 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-23 02:15:00 +0000 (Wed, 23 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-4946-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4946-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4946-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) announced via the USN-4946-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the DRM subsystem in the Linux kernel contained
double-free vulnerabilities. A privileged attacker could possibly use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2021-20292)

Olivier Benjamin, Norbert Manthey, Martin Mazein, and Jan H. Schonherr
discovered that the Xen paravirtualization backend in the Linux kernel did
not properly propagate errors to frontend drivers in some situations. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-26930)

Jan Beulich discovered that multiple Xen backends in the Linux kernel did
not properly handle certain error conditions under paravirtualization. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-26931)

Jan Beulich discovered that the Xen netback backend in the Linux kernel did
not properly handle certain error conditions under paravirtualization. An
attacker in a guest VM could possibly use this to cause a denial of service
(host domain crash). (CVE-2021-28038)

It was discovered that the Xen paravirtualization backend in the Linux
kernel did not properly deallocate memory in some situations. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2021-28688)

It was discovered that the Freescale Gianfar Ethernet driver for the Linux
kernel did not properly handle receive queue overrun when jumbo frames were
enabled in some situations. An attacker could use this to cause a denial of
service (system crash). (CVE-2021-29264)

It was discovered that the USB/IP driver in the Linux kernel contained race
conditions during the update of local and shared status. An attacker could
use this to cause a denial of service (system crash). (CVE-2021-29265)

It was discovered that a race condition existed in the netfilter subsystem
of the Linux kernel when replacing tables. A local attacker could use this
to cause a denial of service (system crash). (CVE-2021-29650)

Arnd Bergmann discovered that the video4linux subsystem in the Linux kernel
did not properly deallocate memory in some situations. A local attacker
could use this to cause a denial of service (memory exhaustion).
(CVE-2021-30002)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-aws-hwe, linux-azure, linux-azure-4.15, linux-dell300x, linux-gcp, linux-gcp-4.15, linux-hwe, linux-kvm, linux-meta, linux-meta-aws, linux-meta-azure-4.15, linux-meta-dell300x, linux-meta-gcp-4.15, linux-meta-kvm, linux-meta-oracle, linux-meta-raspi2, linux-meta-snapdragon, linux-oracle, linux-raspi2, linux-signed, linux-signed-azure-4.15, linux-signed-dell300x, linux-signed-gcp-4.15, linux-signed-oracle, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
