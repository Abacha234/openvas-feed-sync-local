# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63959");
  script_cve_id("CVE-2008-4307", "CVE-2008-5395", "CVE-2008-5701", "CVE-2008-5702", "CVE-2008-5713", "CVE-2009-0028", "CVE-2009-0029", "CVE-2009-0031", "CVE-2009-0065", "CVE-2009-0322", "CVE-2009-0675", "CVE-2009-0676", "CVE-2009-0834", "CVE-2009-0859", "CVE-2009-1192", "CVE-2009-1265", "CVE-2009-1336", "CVE-2009-1337", "CVE-2009-1439");
  script_tag(name:"creation_date", value:"2009-05-11 18:24:31 +0000 (Mon, 11 May 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1794)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1794");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1794");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fai-kernels, linux-2.6, user-mode-linux' package(s) announced via the DSA-1794 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to denial of service, privilege escalation, or information leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-4307

Bryn M. Reeves reported a denial of service in the NFS filesystem. Local users can trigger a kernel BUG() due to a race condition in the do_setlk function.

CVE-2008-5395

Helge Deller discovered a denial of service condition that allows local users on PA-RISC to crash the system by attempting to unwind a stack containing userspace addresses.

CVE-2008-5701

Vlad Malov reported an issue on 64-bit MIPS where a local user could cause a system crash by crafting a malicious binary which makes o32 syscalls with a number less than 4000.

CVE-2008-5702

Zvonimir Rakamaric reported an off-by-one error in the ib700wdt watchdog driver which allows local users to cause a buffer underflow by making a specially crafted WDIOC_SETTIMEOUT ioctl call.

CVE-2008-5713

Flavio Leitner discovered that a local user can cause a denial of service by generating large amounts of traffic on a large SMP system, resulting in soft lockups.

CVE-2009-0028

Chris Evans discovered a situation in which a child process can send an arbitrary signal to its parent.

CVE-2009-0029

Christian Borntraeger discovered an issue effecting the alpha, mips, powerpc, s390 and sparc64 architectures that allows local users to cause a denial of service or potentially gain elevated privileges.

CVE-2009-0031

Vegard Nossum discovered a memory leak in the keyctl subsystem that allows local users to cause a denial of service by consuming all available kernel memory.

CVE-2009-0065

Wei Yongjun discovered a memory overflow in the SCTP implementation that can be triggered by remote users, permitting remote code execution.

CVE-2009-0322

Pavel Roskin provided a fix for an issue in the dell_rbu driver that allows a local user to cause a denial of service (oops) by reading 0 bytes from a sysfs entry.

CVE-2009-0675

Roel Kluin discovered inverted logic in the skfddi driver that permits local, unprivileged users to reset the driver statistics.

CVE-2009-0676

Clement LECIGNE discovered a bug in the sock_getsockopt function that may result in leaking sensitive kernel memory.

CVE-2009-0834

Roland McGrath discovered an issue on amd64 kernels that allows local users to circumvent system call audit configurations which filter based on the syscall numbers or argument details.

CVE-2009-0859

Jiri Olsa discovered that a local user can cause a denial of service (system hang) using a SHM_INFO shmctl call on kernels compiled with CONFIG_SHMEM disabled. This issue does not affect prebuilt Debian kernels.

CVE-2009-1192

Shaohua Li reported an issue in the AGP subsystem that may allow local users to read sensitive kernel memory due to a leak of uninitialized memory.

CVE-2009-1265

Thomas Pollet ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'fai-kernels, linux-2.6, user-mode-linux' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);