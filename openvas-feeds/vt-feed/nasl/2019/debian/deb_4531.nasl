# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704531");
  script_cve_id("CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15902");
  script_tag(name:"creation_date", value:"2019-09-26 02:00:16 +0000 (Thu, 26 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-02 15:44:00 +0000 (Wed, 02 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-4531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4531");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4531");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-4531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2019-14821

Matt Delco reported a race condition in KVM's coalesced MMIO facility, which could lead to out-of-bounds access in the kernel. A local attacker permitted to access /dev/kvm could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation.

CVE-2019-14835

Peter Pi of Tencent Blade Team discovered a missing bounds check in vhost_net, the network back-end driver for KVM hosts, leading to a buffer overflow when the host begins live migration of a VM. An attacker in control of a VM could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation on the host.

CVE-2019-15117

Hui Peng and Mathias Payer reported a missing bounds check in the usb-audio driver's descriptor parsing code, leading to a buffer over-read. An attacker able to add USB devices could possibly use this to cause a denial of service (crash).

CVE-2019-15118

Hui Peng and Mathias Payer reported unbounded recursion in the usb-audio driver's descriptor parsing code, leading to a stack overflow. An attacker able to add USB devices could use this to cause a denial of service (memory corruption or crash) or possibly for privilege escalation. On the amd64 architecture, and on the arm64 architecture in buster, this is mitigated by a guard page on the kernel stack, so that it is only possible to cause a crash.

CVE-2019-15902

Brad Spengler reported that a backporting error reintroduced a spectre-v1 vulnerability in the ptrace subsystem in the ptrace_get_debugreg() function.

For the oldstable distribution (stretch), these problems have been fixed in version 4.9.189-3+deb9u1.

For the stable distribution (buster), these problems have been fixed in version 4.19.67-2+deb10u1.

We recommend that you upgrade your linux packages.

For the detailed security status of linux please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);