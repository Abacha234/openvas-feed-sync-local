# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840544");
  script_cve_id("CVE-2010-2955", "CVE-2010-3848", "CVE-2010-3849", "CVE-2010-3850", "CVE-2010-4082", "CVE-2013-2128");
  script_tag(name:"creation_date", value:"2010-12-09 07:26:35 +0000 (Thu, 09 Dec 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 16:35:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1023-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1023-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1023-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-ec2, linux-source-2.6.15' package(s) announced via the USN-1023-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Nelson Elhage discovered several problems with the Acorn Econet protocol
driver. A local user could cause a denial of service via a NULL pointer
dereference, escalate privileges by overflowing the kernel stack, and
assign Econet addresses to arbitrary interfaces. (CVE-2010-3848,
CVE-2010-3849, CVE-2010-3850)

Brad Spengler discovered that the wireless extensions did not correctly
validate certain request sizes. A local attacker could exploit this to read
portions of kernel memory, leading to a loss of privacy. (CVE-2010-2955)

Dan Rosenberg discovered that the VIA video driver did not correctly clear
kernel memory. A local attacker could exploit this to read kernel stack
memory, leading to a loss of privacy. (CVE-2010-4082)

A flaw was discovered in the Linux kernel's splice system call. A local
user could use this flaw to cause a denial of service (system crash).
(CVE-2013-2128)");

  script_tag(name:"affected", value:"'linux, linux-ec2, linux-source-2.6.15' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
