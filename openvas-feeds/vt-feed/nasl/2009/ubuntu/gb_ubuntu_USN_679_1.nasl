# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840288");
  script_cve_id("CVE-2007-5498", "CVE-2008-3831", "CVE-2008-4210", "CVE-2008-4554", "CVE-2008-4576", "CVE-2008-4618", "CVE-2008-4933", "CVE-2008-4934", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5033");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-679-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-679-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-679-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-backports-modules-2.6.15, linux-backports-modules-2.6.22, linux-backports-modules-2.6.24, linux-backports-modules-2.6.27, linux-restricted-modules, linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.22, linux-restricted-modules-2.6.24, linux-source-2.6.15, linux-source-2.6.22, linux-ubuntu-modules-2.6.22, linux-ubuntu-modules-2.6.24' package(s) announced via the USN-679-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Xen hypervisor block driver did not correctly
validate requests. A user with root privileges in a guest OS could make a
malicious IO request with a large number of blocks that would crash the
host OS, leading to a denial of service. This only affected Ubuntu 7.10.
(CVE-2007-5498)

It was discovered the i915 video driver did not correctly validate
memory addresses. A local attacker could exploit this to remap memory that
could cause a system crash, leading to a denial of service. This issue did
not affect Ubuntu 6.06 and was previous fixed for Ubuntu 7.10 and 8.04 in
USN-659-1. Ubuntu 8.10 has now been corrected as well. (CVE-2008-3831)

David Watson discovered that the kernel did not correctly strip permissions
when creating files in setgid directories. A local user could exploit this
to gain additional group privileges. This issue only affected Ubuntu 6.06.
(CVE-2008-4210)

Olaf Kirch and Miklos Szeredi discovered that the Linux kernel did
not correctly reject the 'append' flag when handling file splice
requests. A local attacker could bypass append mode and make changes to
arbitrary locations in a file. This issue only affected Ubuntu 7.10 and
8.04. (CVE-2008-4554)

It was discovered that the SCTP stack did not correctly handle INIT-ACK. A
remote user could exploit this by sending specially crafted SCTP traffic
which would trigger a crash in the system, leading to a denial of service.
This issue did not affect Ubuntu 8.10. (CVE-2008-4576)

It was discovered that the SCTP stack did not correctly handle bad packet
lengths. A remote user could exploit this by sending specially crafted SCTP
traffic which would trigger a crash in the system, leading to a denial of
service. This issue did not affect Ubuntu 8.10. (CVE-2008-4618)

Eric Sesterhenn discovered multiple flaws in the HFS+ filesystem. If a
local user or automated system were tricked into mounting a malicious HFS+
filesystem, the system could crash, leading to a denial of service.
(CVE-2008-4933, CVE-2008-4934, CVE-2008-5025)

It was discovered that the Unix Socket handler did not correctly process
the SCM_RIGHTS message. A local attacker could make a malicious socket
request that would crash the system, leading to a denial of service.
(CVE-2008-5029)

It was discovered that the driver for simple i2c audio interfaces did not
correctly validate certain function pointers. A local user could exploit
this to gain root privileges or crash the system, leading to a denial of
service. (CVE-2008-5033)");

  script_tag(name:"affected", value:"'linux, linux-backports-modules-2.6.15, linux-backports-modules-2.6.22, linux-backports-modules-2.6.24, linux-backports-modules-2.6.27, linux-restricted-modules, linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.22, linux-restricted-modules-2.6.24, linux-source-2.6.15, linux-source-2.6.22, linux-ubuntu-modules-2.6.22, linux-ubuntu-modules-2.6.24' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
