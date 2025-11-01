# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841675");
  script_cve_id("CVE-2013-4345", "CVE-2013-4588", "CVE-2013-6378", "CVE-2013-6763");
  script_tag(name:"creation_date", value:"2014-01-06 10:32:41 +0000 (Mon, 06 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 17:50:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-2065-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2065-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2065-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-ec2' package(s) announced via the USN-2065-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephan Mueller reported an error in the Linux kernel's ansi cprng random
number generator. This flaw makes it easier for a local attacker to break
cryptographic protections. (CVE-2013-4345)

A flaw was discovered in the Linux kernel's IP Virtual Server (IP_VS)
support. A local user with the CAP_NET_ADMIN capability could exploit this
flaw to gain additional administrative privileges. (CVE-2013-4588)

Nico Golde and Fabian Yamaguchi reported a flaw in the Linux kernel's
debugfs filesystem. An administrative local user could exploit this flaw to
cause a denial of service (OOPS). (CVE-2013-6378)

Nico Golde reported a flaw in the Linux kernel's userspace IO (uio) driver.
A local user could exploit this flaw to cause a denial of service (memory
corruption) or possibly gain privileges. (CVE-2013-6763)");

  script_tag(name:"affected", value:"'linux-ec2' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
