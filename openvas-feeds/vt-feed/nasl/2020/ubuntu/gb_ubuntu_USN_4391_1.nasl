# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844461");
  script_cve_id("CVE-2019-19319", "CVE-2020-0543", "CVE-2020-10751", "CVE-2020-12114", "CVE-2020-12464", "CVE-2020-12769", "CVE-2020-12826", "CVE-2020-1749");
  script_tag(name:"creation_date", value:"2020-06-10 03:01:29 +0000 (Wed, 10 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-22 08:15:00 +0000 (Tue, 22 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4391-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4391-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4391-1");
  script_xref(name:"URL", value:"https://wiki.ubuntu.com/SecurityTeam/KnowledgeBase/SRBDS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-signed' package(s) announced via the USN-4391-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the ext4 file system implementation in the Linux
kernel did not properly handle setxattr operations in some situations. A
local attacker could use this to cause a denial of service (system crash)
or possibly execute arbitrary code. (CVE-2019-19319)

It was discovered that memory contents previously stored in
microarchitectural special registers after RDRAND, RDSEED, and SGX EGETKEY
read operations on Intel client and Xeon E3 processors may be briefly
exposed to processes on the same or different processor cores. A local
attacker could use this to expose sensitive information. (CVE-2020-0543)

Piotr Krysiuk discovered that race conditions existed in the file system
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (system crash). (CVE-2020-12114)

It was discovered that the USB susbsystem's scatter-gather implementation
in the Linux kernel did not properly take data references in some
situations, leading to a use-after-free. A physically proximate attacker
could use this to cause a denial of service (system crash) or possibly
execute arbitrary code. (CVE-2020-12464)

It was discovered that the DesignWare SPI controller driver in the Linux
kernel contained a race condition. A local attacker could possibly use this
to cause a denial of service (system crash). (CVE-2020-12769)

It was discovered that the exit signaling implementation in the Linux
kernel contained an integer overflow. A local attacker could use this to
cause a denial of service (arbitrary application crash). (CVE-2020-12826)

Xiumei Mu discovered that the IPSec implementation in the Linux kernel did
not properly encrypt IPv6 traffic in some situations. An attacker could use
this to expose sensitive information. (CVE-2020-1749)

Dmitry Vyukov discovered that the SELinux netlink security hook in the
Linux kernel did not validate messages in some situations. A privileged
attacker could use this to bypass SELinux netlink restrictions.
(CVE-2020-10751)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial, linux-meta, linux-meta-aws, linux-meta-kvm, linux-signed' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
