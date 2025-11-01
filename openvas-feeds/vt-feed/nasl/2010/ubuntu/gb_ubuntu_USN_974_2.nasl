# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840486");
  script_cve_id("CVE-2010-2240", "CVE-2010-2803", "CVE-2010-2959");
  script_tag(name:"creation_date", value:"2010-08-30 14:59:25 +0000 (Mon, 30 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-974-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-974-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-974-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/620994");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-974-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-974-1 fixed vulnerabilities in the Linux kernel. The fixes for
CVE-2010-2240 caused failures for Xen hosts. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 Gael Delalleu, Rafal Wojtczuk, and Brad Spengler discovered that the memory
 manager did not properly handle when applications grow stacks into adjacent
 memory regions. A local attacker could exploit this to gain control of
 certain applications, potentially leading to privilege escalation, as
 demonstrated in attacks against the X server. (CVE-2010-2240)

 Kees Cook discovered that under certain situations the ioctl subsystem for
 DRM did not properly sanitize its arguments. A local attacker could exploit
 this to read previously freed kernel memory, leading to a loss of privacy.
 (CVE-2010-2803)

 Ben Hawkes discovered an integer overflow in the Controller Area Network
 (CAN) subsystem when setting up frame content and filtering certain
 messages. An attacker could send specially crafted CAN traffic to crash the
 system or gain root privileges. (CVE-2010-2959)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 8.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
