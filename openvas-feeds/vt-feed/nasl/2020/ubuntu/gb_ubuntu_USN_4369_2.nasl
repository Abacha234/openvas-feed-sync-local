# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844448");
  script_cve_id("CVE-2019-19377", "CVE-2019-19769", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668", "CVE-2020-12657");
  script_tag(name:"creation_date", value:"2020-05-29 03:00:28 +0000 (Fri, 29 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4369-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4369-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4369-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1879690");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-meta-raspi2, linux-meta-raspi2-5.3, linux-raspi2, linux-raspi2-5.3, linux-signed' package(s) announced via the USN-4369-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4369-1 fixed vulnerabilities in the 5.3 Linux kernel. Unfortunately,
that update introduced a regression in overlayfs. This update corrects
the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the btrfs implementation in the Linux kernel did not
 properly detect that a block was marked dirty in some situations. An
 attacker could use this to specially craft a file system image that, when
 unmounted, could cause a denial of service (system crash). (CVE-2019-19377)

 Tristan Madani discovered that the file locking implementation in the Linux
 kernel contained a race condition. A local attacker could possibly use this
 to cause a denial of service or expose sensitive information.
 (CVE-2019-19769)

 It was discovered that the Serial CAN interface driver in the Linux kernel
 did not properly initialize data. A local attacker could use this to expose
 sensitive information (kernel memory). (CVE-2020-11494)

 It was discovered that the linux kernel did not properly validate certain
 mount options to the tmpfs virtual memory file system. A local attacker
 with the ability to specify mount options could use this to cause a denial
 of service (system crash). (CVE-2020-11565)

 It was discovered that the OV51x USB Camera device driver in the Linux
 kernel did not properly validate device metadata. A physically proximate
 attacker could use this to cause a denial of service (system crash).
 (CVE-2020-11608)

 It was discovered that the STV06XX USB Camera device driver in the Linux
 kernel did not properly validate device metadata. A physically proximate
 attacker could use this to cause a denial of service (system crash).
 (CVE-2020-11609)

 It was discovered that the Xirlink C-It USB Camera device driver in the
 Linux kernel did not properly validate device metadata. A physically
 proximate attacker could use this to cause a denial of service (system
 crash). (CVE-2020-11668)

 It was discovered that the block layer in the Linux kernel contained a race
 condition leading to a use-after-free vulnerability. A local attacker could
 possibly use this to cause a denial of service (system crash) or execute
 arbitrary code. (CVE-2020-12657)");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-meta-raspi2, linux-meta-raspi2-5.3, linux-raspi2, linux-raspi2-5.3, linux-signed' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
