# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702469");
  script_cve_id("CVE-2011-4086", "CVE-2012-0879", "CVE-2012-1601", "CVE-2012-2123", "CVE-2012-2133");
  script_tag(name:"creation_date", value:"2013-09-18 09:53:02 +0000 (Wed, 18 Sep 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 10:10:00 +0000 (Fri, 31 Jul 2020)");

  script_name("Debian: Security Advisory (DSA-2469)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2469");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2469");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-2469 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or privilege escalation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2011-4086

Eric Sandeen reported an issue in the journaling layer for ext4 filesystems (jbd2). Local users can cause buffers to be accessed after they have been torn down, resulting in a denial of service (DoS) due to a system crash.

CVE-2012-0879

Louis Rilling reported two reference counting issues in the CLONE_IO feature of the kernel. Local users can prevent io context structures from being freed, resulting in a denial of service.

CVE-2012-1601

Michael Ellerman reported an issue in the KVM subsystem. Local users could cause a denial of service (NULL pointer dereference) by creating VCPUs before a call to KVM_CREATE_IRQCHIP.

CVE-2012-2123

Steve Grubb reported an issue in fcaps, a filesystem-based capabilities system. Personality flags set using this mechanism, such as the disabling of address space randomization, may persist across suid calls.

CVE-2012-2133

Shachar Raindel discovered a use-after-free bug in the hugepages quota implementation. Local users with permission to use hugepages via the hugetlbfs implementation may be able to cause a denial of service (system crash).

For the stable distribution (squeeze), this problem has been fixed in version 2.6.32-44. Updates are currently only available for the amd64, i386 and sparc ports.

Note: updated linux-2.6 packages will also be made available in the release of Debian 6.0.5, scheduled to take place the weekend of 2012.05.12. This pending update will be version 2.6.32-45, and provides an additional fix for build failures on some architectures. Users for whom this update is not critical, and who may wish to avoid multiple reboots, should consider waiting for the 6.0.5 release before updating, or installing the 2.6.32-45 version ahead of time from proposed-updates.

The following matrix lists additional source packages that were rebuilt for compatibility with or to take advantage of this update:



Debian 6.0 (squeeze)

user-mode-linux

2.6.32-1um-4+44

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);