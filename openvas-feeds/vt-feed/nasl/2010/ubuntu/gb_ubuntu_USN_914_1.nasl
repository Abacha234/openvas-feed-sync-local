# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840403");
  script_cve_id("CVE-2010-0307", "CVE-2010-0309", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622", "CVE-2010-0623");
  script_tag(name:"creation_date", value:"2010-03-22 10:34:53 +0000 (Mon, 22 Mar 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-914-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-914-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2, linux-fsl-imx51, linux-mvl-dove, linux-source-2.6.15' package(s) announced via the USN-914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathias Krause discovered that the Linux kernel did not correctly handle
missing ELF interpreters. A local attacker could exploit this to cause the
system to crash, leading to a denial of service. (CVE-2010-0307)

Marcelo Tosatti discovered that the Linux kernel's hardware virtualization
did not correctly handle reading the /dev/port special device. A local
attacker in a guest operating system could issue a specific read that
would cause the host system to crash, leading to a denial of service.
(CVE-2010-0309)

Sebastian Krahmer discovered that the Linux kernel did not correctly
handle netlink connector messages. A local attacker could exploit this
to consume kernel memory, leading to a denial of service. (CVE-2010-0410)

Ramon de Carvalho Valle discovered that the Linux kernel did not correctly
validate certain memory migration calls. A local attacker could exploit
this to read arbitrary kernel memory or cause a system crash, leading
to a denial of service. (CVE-2010-0415)

Jermome Marchand and Mikael Pettersson discovered that the Linux kernel
did not correctly handle certain futex operations. A local attacker could
exploit this to cause a system crash, leading to a denial of service.
(CVE-2010-0622, CVE-2010-0623)");

  script_tag(name:"affected", value:"'linux, linux-ec2, linux-fsl-imx51, linux-mvl-dove, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
