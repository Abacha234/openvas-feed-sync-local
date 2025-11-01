# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64034");
  script_cve_id("CVE-2009-0028", "CVE-2009-0834", "CVE-2009-0835", "CVE-2009-0859", "CVE-2009-1046", "CVE-2009-1072", "CVE-2009-1184", "CVE-2009-1192", "CVE-2009-1242", "CVE-2009-1265", "CVE-2009-1337", "CVE-2009-1338", "CVE-2009-1439");
  script_tag(name:"creation_date", value:"2009-05-25 18:59:33 +0000 (Mon, 25 May 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1800)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1800");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1800");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6, user-mode-linux' package(s) announced via the DSA-1800 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service, privilege escalation or a sensitive memory leak. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0028

Chris Evans discovered a situation in which a child process can send an arbitrary signal to its parent.

CVE-2009-0834

Roland McGrath discovered an issue on amd64 kernels that allows local users to circumvent system call audit configurations which filter based on the syscall numbers or argument details.

CVE-2009-0835

Roland McGrath discovered an issue on amd64 kernels with CONFIG_SECCOMP enabled. By making a specially crafted syscall, local users can bypass access restrictions.

CVE-2009-0859

Jiri Olsa discovered that a local user can cause a denial of service (system hang) using a SHM_INFO shmctl call on kernels compiled with CONFIG_SHMEM disabled. This issue does not affect prebuilt Debian kernels.

CVE-2009-1046

Mikulas Patocka reported an issue in the console subsystem that allows a local user to cause memory corruption by selecting a small number of 3-byte UTF-8 characters.

CVE-2009-1072

Igor Zhbanov reported that nfsd was not properly dropping CAP_MKNOD, allowing users to create device nodes on file systems exported with root_squash.

CVE-2009-1184

Dan Carpenter reported a coding issue in the selinux subsystem that allows local users to bypass certain networking checks when running with compat_net=1.

CVE-2009-1192

Shaohua Li reported an issue in the AGP subsystem they may allow local users to read sensitive kernel memory due to a leak of uninitialized memory.

CVE-2009-1242

Benjamin Gilbert reported a local denial of service vulnerability in the KVM VMX implementation that allows local users to trigger an oops.

CVE-2009-1265

Thomas Pollet reported an overflow in the af_rose implementation that allows remote attackers to retrieve uninitialized kernel memory that may contain sensitive data.

CVE-2009-1337

Oleg Nesterov discovered an issue in the exit_notify function that allows local users to send an arbitrary signal to a process by running a program that modifies the exit_signal field and then uses an exec system call to launch a setuid application.

CVE-2009-1338

Daniel Hokka Zakrisson discovered that a kill(-1) is permitted to reach processes outside of the current process namespace.

CVE-2009-1439

Pavan Naregundi reported an issue in the CIFS filesystem code that allows remote users to overwrite memory via a long nativeFileSystem field in a Tree Connect response during mount.

For the oldstable distribution (etch), these problems, where applicable, will be fixed in future updates to linux-2.6 and linux-2.6.24.

For the stable distribution (lenny), these problems have been fixed in version 2.6.26-15lenny2.

We recommend that you upgrade your linux-2.6 and user-mode-linux packages.

Note: Debian ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-2.6, user-mode-linux' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);