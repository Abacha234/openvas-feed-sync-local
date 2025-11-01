# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843498");
  script_cve_id("CVE-2017-11089", "CVE-2017-12762", "CVE-2017-17448", "CVE-2017-17741", "CVE-2017-17805", "CVE-2017-17807", "CVE-2018-1000026", "CVE-2018-5332");
  script_tag(name:"creation_date", value:"2018-04-06 07:57:34 +0000 (Fri, 06 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-06 01:29:00 +0000 (Fri, 06 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3620-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3620-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3620-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta' package(s) announced via the USN-3620-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the netlink 802.11 configuration interface in the
Linux kernel did not properly validate some attributes passed from
userspace. A local attacker with the CAP_NET_ADMIN privilege could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-11089)

It was discovered that a buffer overflow existed in the ioctl handling code
in the ISDN subsystem of the Linux kernel. A local attacker could use this
to cause a denial of service (system crash) or possibly execute arbitrary
code. (CVE-2017-12762)

It was discovered that the netfilter component of the Linux did not
properly restrict access to the connection tracking helpers list. A local
attacker could use this to bypass intended access restrictions.
(CVE-2017-17448)

Dmitry Vyukov discovered that the KVM implementation in the Linux kernel
contained an out-of-bounds read when handling memory-mapped I/O. A local
attacker could use this to expose sensitive information. (CVE-2017-17741)

It was discovered that the Salsa20 encryption algorithm implementations in
the Linux kernel did not properly handle zero-length inputs. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2017-17805)

It was discovered that the keyring implementation in the Linux kernel did
not properly check permissions when a key request was performed on a
task's default keyring. A local attacker could use this to add keys to
unauthorized keyrings. (CVE-2017-17807)

It was discovered that the Broadcom NetXtremeII ethernet driver in the
Linux kernel did not properly validate Generic Segment Offload (GSO) packet
sizes. An attacker could use this to cause a denial of service (interface
unavailability). (CVE-2018-1000026)

It was discovered that the Reliable Datagram Socket (RDS) implementation in
the Linux kernel contained an out-of-bounds write during RDMA page
allocation. An attacker could use this to cause a denial of service (system
crash) or possibly execute arbitrary code. (CVE-2018-5332)");

  script_tag(name:"affected", value:"'linux, linux-meta' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
