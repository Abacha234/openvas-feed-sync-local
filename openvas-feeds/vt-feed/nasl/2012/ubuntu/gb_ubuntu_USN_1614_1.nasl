# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841196");
  script_cve_id("CVE-2012-4464", "CVE-2012-4466", "CVE-2012-4522");
  script_tag(name:"creation_date", value:"2012-10-23 03:59:09 +0000 (Tue, 23 Oct 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Ubuntu: Security Advisory (USN-1614-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1614-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1614-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby1.9.1' package(s) announced via the USN-1614-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tyler Hicks and Shugo Maeda discovered that Ruby incorrectly allowed untainted
strings to be modified in protective safe levels. An attacker could use this
flaw to bypass intended access restrictions. USN-1602-1 fixed these
vulnerabilities in other Ubuntu releases. This update provides the
corresponding updates for Ubuntu 12.10. (CVE-2012-4464, CVE-2012-4466)

Peter Bex discovered that Ruby incorrectly handled file path strings when
opening files. An attacker could use this flaw to open or create unexpected
files. (CVE-2012-4522)");

  script_tag(name:"affected", value:"'ruby1.9.1' package(s) on Ubuntu 12.04, Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
