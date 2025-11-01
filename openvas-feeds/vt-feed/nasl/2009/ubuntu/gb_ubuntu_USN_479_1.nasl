# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840081");
  script_cve_id("CVE-2006-7177", "CVE-2006-7178", "CVE-2006-7179", "CVE-2006-7180", "CVE-2007-2829", "CVE-2007-2830", "CVE-2007-2831");
  script_tag(name:"creation_date", value:"2009-03-23 09:55:18 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-479-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-479-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-479-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.17, linux-restricted-modules-2.6.20' package(s) announced via the USN-479-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws in the MadWifi driver were discovered that could lead
to a system crash. A physically near-by attacker could generate
specially crafted wireless network traffic and cause a denial of
service. (CVE-2006-7177, CVE-2006-7178, CVE-2006-7179, CVE-2007-2829,
CVE-2007-2830)

A flaw was discovered in the MadWifi driver that would allow unencrypted
network traffic to be sent prior to finishing WPA authentication.
A physically near-by attacker could capture this, leading to a loss of
privacy, denial of service, or network spoofing. (CVE-2006-7180)

A flaw was discovered in the MadWifi driver's ioctl handling. A local
attacker could read kernel memory, or crash the system, leading to a
denial of service. (CVE-2007-2831)");

  script_tag(name:"affected", value:"'linux-restricted-modules-2.6.15, linux-restricted-modules-2.6.17, linux-restricted-modules-2.6.20' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
