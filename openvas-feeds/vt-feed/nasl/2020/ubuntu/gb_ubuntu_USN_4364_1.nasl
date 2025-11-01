# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844433");
  script_cve_id("CVE-2019-19060", "CVE-2020-10942", "CVE-2020-11494", "CVE-2020-11565", "CVE-2020-11608", "CVE-2020-11609", "CVE-2020-11668");
  script_tag(name:"creation_date", value:"2020-05-19 03:00:28 +0000 (Tue, 19 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4364-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4364-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4364-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) announced via the USN-4364-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ADIS16400 IIO IMU Driver for the Linux kernel
did not properly deallocate memory in certain error conditions. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2019-19060)

It was discovered that the vhost net driver in the Linux kernel contained a
stack buffer overflow. A local attacker with the ability to perform ioctl()
calls on /dev/vhost-net could use this to cause a denial of service (system
crash). (CVE-2020-10942)

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
crash). (CVE-2020-11668)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-raspi2, linux-meta-snapdragon, linux-raspi2, linux-signed, linux-snapdragon' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
