# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58337");
  script_cve_id("CVE-2007-0005", "CVE-2007-0958", "CVE-2007-1357", "CVE-2007-1592");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-1286)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1286");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1286");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DSA-1286 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local and remote vulnerabilities have been discovered in the Linux kernel that may lead to a denial of service or the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-0005

Daniel Roethlisberger discovered two buffer overflows in the cm4040 driver for the Omnikey CardMan 4040 device. A local user or malicious device could exploit this to execute arbitrary code in kernel space.

CVE-2007-0958

Santosh Eraniose reported a vulnerability that allows local users to read otherwise unreadable files by triggering a core dump while using PT_INTERP. This is related to CVE-2004-1073.

CVE-2007-1357

Jean Delvare reported a vulnerability in the appletalk subsystem. Systems with the appletalk module loaded can be triggered to crash by other systems on the local network via a malformed frame.

CVE-2007-1592

Masayuki Nakagawa discovered that flow labels were inadvertently being shared between listening sockets and child sockets. This defect can be exploited by local users to cause a DoS (Oops).

This problem has been fixed in the stable distribution in version 2.6.18.dfsg.1-12etch1.

The following matrix lists additional packages that were rebuilt for compatibility with or to take advantage of this update:

Debian 4.0 (etch)

fai-kernels 1.17etch1

user-mode-linux 2.6.18-1um-2etch1

We recommend that you upgrade your kernel package immediately and reboot the machine. If you have built a custom kernel from the kernel source package, you will need to rebuild to take advantage of these fixes.

Updated packages for the mips and mipsel architectures are not yet available. They will be provided later.");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);