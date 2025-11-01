# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841518");
  script_cve_id("CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2851");
  script_tag(name:"creation_date", value:"2013-08-08 06:16:02 +0000 (Thu, 08 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1912-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1912-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1912-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1912-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jonathan Salwan discovered an information leak in the Linux kernel's cdrom
driver. A local user can exploit this leak to obtain sensitive information
from kernel memory if the CD-ROM drive is malfunctioning. (CVE-2013-2164)

A flaw was discovered in the Linux kernel when an IPv6 socket is used to
connect to an IPv4 destination. An unprivileged local user could exploit
this flaw to cause a denial of service (system crash). (CVE-2013-2232)

An information leak was discovered in the IPSec key_socket implementation
in the Linux kernel. An local user could exploit this flaw to examine
potentially sensitive information in kernel memory. (CVE-2013-2234)

An information leak was discovered in the Linux kernel when reading
broadcast messages from the notify_policy interface of the IPSec
key_socket. A local user could exploit this flaw to examine potentially
sensitive information in kernel memory.
(CVE-2013-2237)

Kees Cook discovered a format string vulnerability in the Linux kernel's
disk block layer. A local user with administrator privileges could exploit
this flaw to gain kernel privileges. (CVE-2013-2851)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
