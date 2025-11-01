# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844896");
  script_cve_id("CVE-2015-1350", "CVE-2017-16644", "CVE-2017-5967", "CVE-2018-13095", "CVE-2019-16231", "CVE-2019-16232", "CVE-2019-19061", "CVE-2021-20261", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-28038");
  script_tag(name:"creation_date", value:"2021-04-14 03:00:32 +0000 (Wed, 14 Apr 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-31 00:15:00 +0000 (Wed, 31 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4904-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4904-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4904-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4904-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ben Harris discovered that the Linux kernel would strip extended privilege
attributes of files when performing a failed unprivileged system call. A
local attacker could use this to cause a denial of service. (CVE-2015-1350)

Andrey Konovalov discovered that the video4linux driver for Hauppauge HD
PVR USB devices in the Linux kernel did not properly handle some error
conditions. A physically proximate attacker could use this to cause a
denial of service (system crash) or possibly execute arbitrary code.
(CVE-2017-16644)

It was discovered that the timer stats implementation in the Linux kernel
allowed the discovery of a real PID value while inside a PID namespace. A
local attacker could use this to expose sensitive information.
(CVE-2017-5967)

Wen Xu discovered that the xfs file system implementation in the Linux
kernel did not properly validate the number of extents in an inode. An
attacker could use this to construct a malicious xfs image that, when
mounted, could cause a denial of service (system crash). (CVE-2018-13095)

It was discovered that the Fujitsu ES network device driver for the Linux
kernel did not properly check for errors in some situations, leading to a
NULL pointer dereference. A local attacker could use this to cause a denial
of service. (CVE-2019-16231)

It was discovered that the Marvell 8xxx Libertas WLAN device driver in the
Linux kernel did not properly check for errors in certain situations,
leading to a NULL pointer dereference. A local attacker could possibly use
this to cause a denial of service. (CVE-2019-16232)

It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19061)

It was discovered that a race condition existed in the floppy device driver
in the Linux kernel. An attacker with access to the floppy device could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2021-20261)

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
(host domain crash). (CVE-2021-28038)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
