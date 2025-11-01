# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843459");
  script_cve_id("CVE-2015-8952", "CVE-2017-12190", "CVE-2017-15115", "CVE-2017-17712", "CVE-2017-5715", "CVE-2017-8824");
  script_tag(name:"creation_date", value:"2018-02-22 14:56:55 +0000 (Thu, 22 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-13 11:29:00 +0000 (Thu, 13 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-3582-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3582-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3582-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial' package(s) announced via the USN-3582-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3582-1 fixed vulnerabilities in the Linux kernel for Ubuntu 16.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 16.04 LTS for Ubuntu
14.04 LTS.

Mohamed Ghannam discovered that the IPv4 raw socket implementation in the
Linux kernel contained a race condition leading to uninitialized pointer
usage. A local attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2017-17712)

Laurent Guerby discovered that the mbcache feature in the ext2 and ext4
filesystems in the Linux kernel improperly handled xattr block caching. A
local attacker could use this to cause a denial of service. (CVE-2015-8952)

Vitaly Mayatskikh discovered that the SCSI subsystem in the Linux kernel
did not properly track reference counts when merging buffers. A local
attacker could use this to cause a denial of service (memory exhaustion).
(CVE-2017-12190)

ChunYu Wang discovered that a use-after-free vulnerability existed in the
SCTP protocol implementation in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code, (CVE-2017-15115)

Mohamed Ghannam discovered a use-after-free vulnerability in the DCCP
protocol implementation in the Linux kernel. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2017-8824)

USN-3540-2 mitigated CVE-2017-5715 (Spectre Variant 2) for the
amd64 architecture in Ubuntu 14.04 LTS. This update provides the
compiler-based retpoline kernel mitigation for the amd64 and i386
architectures. Original advisory details:

 Jann Horn discovered that microprocessors utilizing speculative execution
 and branch prediction may allow unauthorized memory reads via sidechannel
 attacks. This flaw is known as Spectre. A local attacker could use this to
 expose sensitive information, including kernel memory. (CVE-2017-5715)");

  script_tag(name:"affected", value:"'linux-aws, linux-lts-xenial, linux-meta-aws, linux-meta-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
