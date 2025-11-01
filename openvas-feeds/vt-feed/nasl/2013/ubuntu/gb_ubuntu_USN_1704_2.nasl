# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841304");
  script_cve_id("CVE-2012-0957", "CVE-2012-4461", "CVE-2012-4508", "CVE-2012-4530", "CVE-2012-4565", "CVE-2012-5517", "CVE-2012-5532");
  script_tag(name:"creation_date", value:"2013-02-04 04:27:45 +0000 (Mon, 04 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1704-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1704-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1704-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1101666");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-quantal' package(s) announced via the USN-1704-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1704-1 fixed vulnerabilities in the Linux kernel. Due to an unrelated
regression inotify/fanotify stopped working after upgrading. This update
fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Brad Spengler discovered a flaw in the Linux kernel's uname system call. An
 unprivileged user could exploit this flaw to read kernel stack memory.
 (CVE-2012-0957)

 Jon Howell reported a flaw in the Linux kernel's KVM (Kernel-based virtual
 machine) subsystem's handling of the XSAVE feature. On hosts, using qemu
 userspace, without the XSAVE feature an unprivileged local attacker could
 exploit this flaw to crash the system. (CVE-2012-4461)

 Dmitry Monakhov reported a race condition flaw the Linux ext4 filesystem
 that can expose stale data. An unprivileged user could exploit this flaw to
 cause an information leak. (CVE-2012-4508)

 A flaw was discovered in the Linux kernel's handling of script execution
 when module loading is enabled. A local attacker could exploit this flaw to
 cause a leak of kernel stack contents. (CVE-2012-4530)

 Rodrigo Freire discovered a flaw in the Linux kernel's TCP illinois
 congestion control algorithm. A local attacker could use this to cause a
 denial of service. (CVE-2012-4565)

 A flaw was discovered in the Linux kernel's handling of new hot-plugged
 memory. An unprivileged local user could exploit this flaw to cause a
 denial of service by crashing the system. (CVE-2012-5517)

 Florian Weimer discovered that hypervkvpd, which is distributed in the
 Linux kernel, was not correctly validating source addresses of netlink
 packets. An untrusted local user can cause a denial of service by causing
 hypervkvpd to exit. (CVE-2012-5532)");

  script_tag(name:"affected", value:"'linux-lts-quantal' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
