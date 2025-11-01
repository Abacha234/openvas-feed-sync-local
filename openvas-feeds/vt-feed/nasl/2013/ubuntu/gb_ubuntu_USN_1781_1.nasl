# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841376");
  script_cve_id("CVE-2013-0228", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0313", "CVE-2013-0349", "CVE-2013-1772", "CVE-2013-1774");
  script_tag(name:"creation_date", value:"2013-03-28 04:20:13 +0000 (Thu, 28 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1781-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1781-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1781-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ti-omap4' package(s) announced via the USN-1781-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Andrew Jones discovered a flaw with the xen_iret function in Linux kernel's
Xen virtualizeation. In the 32-bit Xen paravirt platform an unprivileged
guest OS user could exploit this flaw to cause a denial of service (crash
the system) or gain guest OS privilege. (CVE-2013-0228)

A flaw was reported in the permission checks done by the Linux kernel for
/dev/cpu/*/msr. A local root user with all capabilities dropped could
exploit this flaw to execute code with full root capabilities.
(CVE-2013-0268)

A flaw was discovered in the Linux kernel's vhost driver used to accelerate
guest networking in KVM based virtual machines. A privileged guest user
could exploit this flaw to crash the host system. (CVE-2013-0311)

A flaw was discovered in the Extended Verification Module (EVM) of the
Linux kernel. An unprivileged local user code exploit this flaw to cause a
denial of service (system crash). (CVE-2013-0313)

An information leak was discovered in the Linux kernel's Bluetooth stack
when HIDP (Human Interface Device Protocol) support is enabled. A local
unprivileged user could exploit this flaw to cause an information leak from
the kernel. (CVE-2013-0349)

A buffer overflow was discovered in the Linux kernel's /dev/kmesg device. A
local user could exploit this flaw to cause a denial of service (system
crash). (CVE-2013-1772)

A flaw was discovered in the Edgeort USB serial converter driver when the
device is disconnected while it is in use. A local user could exploit this
flaw to cause a denial of service (system crash). (CVE-2013-1774)");

  script_tag(name:"affected", value:"'linux-ti-omap4' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
