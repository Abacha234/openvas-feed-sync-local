# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840565");
  script_cve_id("CVE-2010-2537", "CVE-2010-2538", "CVE-2010-2943", "CVE-2010-2962", "CVE-2010-3079", "CVE-2010-3296", "CVE-2010-3297", "CVE-2010-3298", "CVE-2010-3301", "CVE-2010-3698", "CVE-2010-3858", "CVE-2010-3861", "CVE-2010-4072", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4157", "CVE-2010-4242", "CVE-2010-4655", "CVE-2014-0205");
  script_tag(name:"creation_date", value:"2011-01-14 15:07:43 +0000 (Fri, 14 Jan 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 14:05:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1041-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1041-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2' package(s) announced via the USN-1041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Louis Rilling and Matthieu Fertre reported a use after free error in the
Linux kernel's futex_wait function. A local user could exploit this flaw to
cause a denial of service (system crash) or possibly gain privileges via a
specially crafted application. (CVE-2014-0205)

Ben Hawkes discovered that the Linux kernel did not correctly filter
registers on 64bit kernels when performing 32bit system calls. On a 64bit
system, a local attacker could manipulate 32bit system calls to gain root
privileges. (CVE-2010-3301)

Dan Rosenberg discovered that the btrfs filesystem did not correctly
validate permissions when using the clone function. A local attacker could
overwrite the contents of file handles that were opened for append-only, or
potentially read arbitrary contents, leading to a loss of privacy.
(CVE-2010-2537, CVE-2010-2538)

Dave Chinner discovered that the XFS filesystem did not correctly order
inode lookups when exported by NFS. A remote attacker could exploit this to
read or write disk blocks that had changed file assignment or had become
unlinked, leading to a loss of privacy. (CVE-2010-2943)

Kees Cook discovered that the Intel i915 graphics driver did not correctly
validate memory regions. A local attacker with access to the video card
could read and write arbitrary kernel memory to gain root privileges.
(CVE-2010-2962)

Robert Swiecki discovered that ftrace did not correctly handle mutexes. A
local attacker could exploit this to crash the kernel, leading to a denial
of service. (CVE-2010-3079)

Dan Rosenberg discovered that several network ioctls did not clear kernel
memory correctly. A local user could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-3296, CVE-2010-3297,
CVE-2010-3298)

It was discovered that KVM did not correctly initialize certain CPU
registers. A local attacker could exploit this to crash the system, leading
to a denial of service. (CVE-2010-3698)

Brad Spengler discovered that stack memory for new a process was not
correctly calculated. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2010-3858)

Kees Cook discovered that the ethtool interface did not correctly clear
kernel memory. A local attacker could read kernel heap memory, leading to a
loss of privacy. (CVE-2010-3861)

Kees Cook and Vasiliy Kulikov discovered that the shm interface did not
clear kernel memory correctly. A local attacker could exploit this to read
kernel stack memory, leading to a loss of privacy. (CVE-2010-4072)

Dan Rosenberg discovered that the RME Hammerfall DSP audio interface driver
did not correctly clear kernel memory. A local attacker could exploit this
to read kernel stack memory, leading to a loss of privacy. (CVE-2010-4080,
CVE-2010-4081)

James Bottomley discovered that the ICP vortex storage array controller
driver did not validate certain sizes. A local attacker on a 64bit ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-ec2' package(s) on Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
