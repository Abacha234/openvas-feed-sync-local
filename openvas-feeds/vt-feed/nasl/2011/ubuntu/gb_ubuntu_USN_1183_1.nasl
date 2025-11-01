# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840716");
  script_cve_id("CVE-2010-4076", "CVE-2010-4077", "CVE-2011-1090", "CVE-2011-1163", "CVE-2011-1577", "CVE-2011-1598", "CVE-2011-1746");
  script_tag(name:"creation_date", value:"2011-08-12 13:49:01 +0000 (Fri, 12 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1183-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1183-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Dan Rosenberg discovered that multiple terminal ioctls did not correctly
initialize structure memory. A local attacker could exploit this to read
portions of kernel stack memory, leading to a loss of privacy.
(CVE-2010-4076, CVE-2010-4077)

Neil Horman discovered that NFSv4 did not correctly handle certain orders
of operation with ACL data. A remote attacker with access to an NFSv4 mount
could exploit this to crash the system, leading to a denial of service.
(CVE-2011-1090)

Timo Warns discovered that OSF partition parsing routines did not correctly
clear memory. A local attacker with physical access could plug in a
specially crafted block device to read kernel memory, leading to a loss of
privacy. (CVE-2011-1163)

Timo Warns discovered that the GUID partition parsing routines did not
correctly validate certain structures. A local attacker with physical
access could plug in a specially crafted block device to crash the system,
leading to a denial of service. (CVE-2011-1577)

Oliver Hartkopp and Dave Jones discovered that the CAN network driver did
not correctly validate certain socket structures. If this driver was
loaded, a local attacker could crash the system, leading to a denial of
service. (CVE-2011-1598)

Vasiliy Kulikov discovered that the AGP driver did not check the size of
certain memory allocations. A local attacker with access to the video
subsystem could exploit this to run the system out of memory, leading to a
denial of service. (CVE-2011-1746)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
