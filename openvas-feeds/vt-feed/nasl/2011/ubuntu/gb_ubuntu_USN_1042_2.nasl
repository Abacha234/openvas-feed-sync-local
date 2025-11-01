# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840566");
  script_cve_id("CVE-2010-3436");
  script_tag(name:"creation_date", value:"2011-01-14 15:07:43 +0000 (Fri, 14 Jan 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1042-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1042-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1042-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/701765");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php5' package(s) announced via the USN-1042-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-1042-1 fixed vulnerabilities in PHP5. The fix for CVE-2010-3436
introduced a regression in the open_basedir restriction handling code.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that attackers might be able to bypass open_basedir()
 restrictions by passing a specially crafted filename. (CVE-2010-3436)");

  script_tag(name:"affected", value:"'php5' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
