# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840728");
  script_cve_id("CVE-2011-2697", "CVE-2011-2964");
  script_tag(name:"creation_date", value:"2011-08-27 14:37:49 +0000 (Sat, 27 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1194-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1194-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1194-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'foomatic-filters' package(s) announced via the USN-1194-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the foomatic-rip Foomatic filter incorrectly
handled command-line options. An attacker could use this flaw to cause
Foomatic to execute arbitrary code as the 'lp' user.

In the default installation, attackers would be isolated by the CUPS
AppArmor profile.");

  script_tag(name:"affected", value:"'foomatic-filters' package(s) on Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
