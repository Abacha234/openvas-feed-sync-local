# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842794");
  script_cve_id("CVE-2015-8839", "CVE-2016-1583", "CVE-2016-2117", "CVE-2016-2187", "CVE-2016-3961", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4558", "CVE-2016-4565", "CVE-2016-4581");
  script_tag(name:"creation_date", value:"2016-06-11 03:27:17 +0000 (Sat, 11 Jun 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Ubuntu: Security Advisory (USN-3005-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3005-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3005-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-xenial' package(s) announced via the USN-3005-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Justin Yackoski discovered that the Atheros L2 Ethernet Driver in the Linux
kernel incorrectly enables scatter/gather I/O. A remote attacker could use
this to obtain potentially sensitive information from kernel memory.
(CVE-2016-2117)

Jann Horn discovered that eCryptfs improperly attempted to use the mmap()
handler of a lower filesystem that did not implement one, causing a
recursive page fault to occur. A local unprivileged attacker could use to
cause a denial of service (system crash) or possibly execute arbitrary code
with administrative privileges. (CVE-2016-1583)

Multiple race conditions where discovered in the Linux kernel's ext4 file
system. A local user could exploit this flaw to cause a denial of service
(disk corruption) by writing to a page that is associated with a different
users file after unsynchronized hole punching and page-fault handling.
(CVE-2015-8839)

Ralf Spenneberg discovered that the Linux kernel's GTCO digitizer USB
device driver did not properly validate endpoint descriptors. An attacker
with physical access could use this to cause a denial of service (system
crash). (CVE-2016-2187)

Vitaly Kuznetsov discovered that the Linux kernel did not properly suppress
hugetlbfs support in X86 paravirtualized guests. An attacker in the guest
OS could cause a denial of service (guest system crash). (CVE-2016-3961)

Kangjie Lu discovered an information leak in the ANSI/IEEE 802.2 LLC type 2
Support implementations in the Linux kernel. A local attacker could use
this to obtain potentially sensitive information from kernel memory.
(CVE-2016-4485)

Kangjie Lu discovered an information leak in the routing netlink socket
interface (rtnetlink) implementation in the Linux kernel. A local attacker
could use this to obtain potentially sensitive information from kernel
memory. (CVE-2016-4486)

Jann Horn discovered that the extended Berkeley Packet Filter (eBPF)
implementation in the Linux kernel could overflow reference counters on
systems with more than 32GB of physical ram and with RLIMIT_MEMLOCK set to
infinite. A local unprivileged attacker could use to create a use-after-
free situation, causing a denial of service (system crash) or possibly gain
administrative privileges. (CVE-2016-4558)

Jann Horn discovered that the InfiniBand interfaces within the Linux kernel
could be coerced into overwriting kernel memory. A local unprivileged
attacker could use this to possibly gain administrative privileges on
systems where InifiniBand related kernel modules are loaded.
(CVE-2016-4565)

It was discovered that in some situations the Linux kernel did not handle
propagated mounts correctly. A local unprivileged attacker could use this
to cause a denial of service (system crash). (CVE-2016-4581)");

  script_tag(name:"affected", value:"'linux-lts-xenial' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
