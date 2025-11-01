# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842421");
  script_cve_id("CVE-2015-4473", "CVE-2015-4487", "CVE-2015-4488", "CVE-2015-4489", "CVE-2015-4491");
  script_tag(name:"creation_date", value:"2015-08-26 07:23:18 +0000 (Wed, 26 Aug 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2712-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2712-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2712-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-2712-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gary Kwong, Christian Holler, and Byron Campen discovered multiple memory
safety issues in Thunderbird. If a user were tricked in to opening a
specially crafted message, an attacker could potentially exploit these to
cause a denial of service via application crash, or execute arbitrary code
with the privileges of user invoking Thunderbird. (CVE-2015-4473)

Ronald Crane reported 3 security issues. If a user were tricked in to
opening a specially crafted message, an attacker could potentially
exploit these, in combination with another security vulnerability, to
cause a denial of service via application crash, or execute arbitrary
code with the privileges of the user invoking Thunderbird. (CVE-2015-4487,
CVE-2015-4488, CVE-2015-4489)

Gustavo Grieco discovered a heap overflow in gdk-pixbuf. If a user were
tricked in to opening a specially crafted message, an attacker could
potentially exploit this to cause a denial of service via application
crash or execute arbitrary code with the privileges of the user invoking
Thunderbird. (CVE-2015-4491)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
