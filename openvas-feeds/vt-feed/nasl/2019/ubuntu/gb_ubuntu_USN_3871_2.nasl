# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843897");
  script_cve_id("CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-14625", "CVE-2018-16882", "CVE-2018-17972");
  script_tag(name:"creation_date", value:"2019-02-05 03:04:54 +0000 (Tue, 05 Feb 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3871-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3871-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3871-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1813663");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1813727");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-meta, linux-signed' package(s) announced via the USN-3871-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3871-1 fixed vulnerabilities in the Linux kernel for Ubuntu 18.04
LTS. Unfortunately, that update introduced regressions with docking
station displays and mounting ext4 file systems with the meta_bg
option enabled. This update fixes the problems.

We apologize for the inconvenience.

Original advisory details:

 Wen Xu discovered that a use-after-free vulnerability existed in the ext4
 filesystem implementation in the Linux kernel. An attacker could use this
 to construct a malicious ext4 image that, when mounted, could cause a
 denial of service (system crash) or possibly execute arbitrary code.
 (CVE-2018-10876, CVE-2018-10879)

 Wen Xu discovered that a buffer overflow existed in the ext4 filesystem
 implementation in the Linux kernel. An attacker could use this to construct
 a malicious ext4 image that, when mounted, could cause a denial of service
 (system crash) or possibly execute arbitrary code. (CVE-2018-10877)

 Wen Xu discovered that an out-of-bounds write vulnerability existed in the
 ext4 filesystem implementation in the Linux kernel. An attacker could use
 this to construct a malicious ext4 image that, when mounted, could cause a
 denial of service (system crash) or possibly execute arbitrary code.
 (CVE-2018-10878, CVE-2018-10882)

 Wen Xu discovered that the ext4 filesystem implementation in the Linux
 kernel did not properly ensure that xattr information remained in inode
 bodies. An attacker could use this to construct a malicious ext4 image
 that, when mounted, could cause a denial of service (system crash).
 (CVE-2018-10880)

 Wen Xu discovered that the ext4 file system implementation in the Linux
 kernel could possibly perform an out of bounds write when updating the
 journal for an inline file. An attacker could use this to construct a
 malicious ext4 image that, when mounted, could cause a denial of service
 (system crash). (CVE-2018-10883)

 It was discovered that a race condition existed in the vsock address family
 implementation of the Linux kernel that could lead to a use-after-free
 condition. A local attacker in a guest virtual machine could use this to
 expose sensitive information (host machine kernel memory). (CVE-2018-14625)

 Cfir Cohen discovered that a use-after-free vulnerability existed in the
 KVM implementation of the Linux kernel, when handling interrupts in
 environments where nested virtualization is in use (nested KVM
 virtualization is not enabled by default in Ubuntu kernels). A local
 attacker in a guest VM could possibly use this to gain administrative
 privileges in a host machine. (CVE-2018-16882)

 Jann Horn discovered that the procfs file system implementation in the
 Linux kernel did not properly restrict the ability to inspect the kernel
 stack of an arbitrary task. A local attacker could use this to expose
 sensitive information. (CVE-2018-17972)

 Jann Horn discovered that the mremap() system call in the Linux ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux, linux-meta, linux-signed' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
