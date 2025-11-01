# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58585");
  script_cve_id("CVE-2007-2172", "CVE-2007-2875", "CVE-2007-3105", "CVE-2007-3843", "CVE-2007-4308");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1363)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1363");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1363");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1363 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2172

Thomas Graf reported a typo in the IPv4 protocol handler that could be used by a local attacker to overrun an array via crafted packets, potentially resulting in a Denial of Service (system crash). The DECnet counterpart of this issue was already fixed in DSA-1356.

CVE-2007-2875

iDefense reported a potential integer underflow in the cpuset filesystem which may permit local attackers to gain access to sensitive kernel memory. This vulnerability is only exploitable if the cpuset filesystem is mounted.

CVE-2007-3105

The PaX Team discovered a potential buffer overflow in the random number generator which may permit local users to cause a denial of service or gain additional privileges. This issue is not believed to effect default Debian installations where only root has sufficient privileges to exploit it.

CVE-2007-3843

A coding error in the CIFS subsystem permits the use of unsigned messages even if the client has configured the system to enforce signing by passing the sec=ntlmv2i mount option. This may allow remote attackers to spoof CIFS network traffic.

CVE-2007-4308

Alan Cox reported an issue in the aacraid driver that allows unprivileged local users to make ioctl calls which should be restricted to admin privileges.

These problems have been fixed in the stable distribution in version 2.6.18.dfsg.1-13etch2.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17+etch5

user-mode-linux 2.6.18-1um-2etch4

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);