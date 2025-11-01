# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893131");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-33655", "CVE-2021-33656", "CVE-2021-4159", "CVE-2022-1462", "CVE-2022-1679", "CVE-2022-2153", "CVE-2022-2318", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26365", "CVE-2022-26373", "CVE-2022-2663", "CVE-2022-3028", "CVE-2022-33740", "CVE-2022-33741", "CVE-2022-33742", "CVE-2022-33744", "CVE-2022-36879", "CVE-2022-36946", "CVE-2022-39188", "CVE-2022-39842", "CVE-2022-40307");
  script_tag(name:"creation_date", value:"2022-10-05 07:22:37 +0000 (Wed, 05 Oct 2022)");
  script_version("2024-08-09T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-08-09 05:05:42 +0000 (Fri, 09 Aug 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-24 22:22:00 +0000 (Tue, 24 May 2022)");

  script_name("Debian: Security Advisory (DLA-3131)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3131");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3131");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/advisory-guidance/post-barrier-return-stack-buffer-predictions.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-3131 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to privilege escalation, denial of service or information leaks.

CVE-2021-4159

A flaw was found in the eBPF verifier which could lead to an out-of-bounds read. If unprivileged use of eBPF is enabled, this could leak sensitive information. This was already disabled by default, which would fully mitigate the vulnerability.

CVE-2021-33655

A user with access to a framebuffer console device could cause a memory out-of-bounds write via the FBIOPUT_VSCREENINFO ioctl.

CVE-2021-33656

A user with access to a framebuffer console device could cause a memory out-of-bounds write via some font setting ioctls. These obsolete ioctls have been removed.

CVE-2022-1462

Yi Zhi Gou reported a race condition in the pty (pseudo-terminal) subsystem that can lead to a slab out-of-bounds write. A local user could exploit this to cause a denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-1679

The syzbot tool found a race condition in the ath9k_htc driver which can lead to a use-after-free. This might be exploitable to cause a denial service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-2153

kangel reported a flaw in the KVM implementation for x86 processors which could lead to a null pointer dereference. A local user permitted to access /dev/kvm could exploit this to cause a denial of service (crash).

CVE-2022-2318

A use-after-free in the Amateur Radio X.25 PLP (Rose) support may result in denial of service.

CVE-2022-2586

A use-after-free in the Netfilter subsystem may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

CVE-2022-2588

Zhenpeng Lin discovered a use-after-free flaw in the cls_route filter implementation which may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

CVE-2022-2663

David Leadbeater reported flaws in the nf_conntrack_irc connection-tracking protocol module. When this module is enabled on a firewall, an external user on the same IRC network as an internal user could exploit its lax parsing to open arbitrary TCP ports in the firewall, to reveal their public IP address, or to block their IRC connection at the firewall.

CVE-2022-3028

Abhishek Shah reported a race condition in the AF_KEY subsystem, which could lead to an out-of-bounds write or read. A local user could exploit this to cause a denial of service (crash or memory corruption), to obtain sensitive information, or possibly for privilege escalation.

CVE-2022-26365, CVE-2022-33740, CVE-2022-33741, CVE-2022-33742 Roger Pau Monne discovered that Xen block and network PV device frontends don't zero out memory regions before sharing them with the backend, which may result in information disclosure. Additionally it was ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);