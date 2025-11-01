# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840518");
  script_cve_id("CVE-2010-3175", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3182", "CVE-2010-3183");
  script_tag(name:"creation_date", value:"2010-10-22 14:42:09 +0000 (Fri, 22 Oct 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-997-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-997-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-997-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.1, xulrunner-1.9.2' package(s) announced via the USN-997-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Nickerson, Jesse Ruderman, Olli Pettay, Igor Bukanov, Josh Soref, Gary
Kwong, Martijn Wargers, Siddharth Agarwal and Michal Zalewski discovered
various flaws in the browser engine. An attacker could exploit this to
crash the browser or possibly run arbitrary code as the user invoking the
program. (CVE-2010-3175, CVE-2010-3176)

Alexander Miller, Sergey Glazunov, and others discovered several flaws in
the JavaScript engine. An attacker could exploit this to crash the browser
or possibly run arbitrary code as the user invoking the program.
(CVE-2010-3179, CVE-2010-3180, CVE-2010-3183)

Robert Swiecki discovered that Firefox did not properly validate Gopher
URLs. If a user were tricked into opening a crafted file via Gopher, an
attacker could possibly run arbitrary JavaScript. (CVE-2010-3177)

Eduardo Vela Nava discovered that Firefox could be made to violate the
same-origin policy by using modal calls with JavaScript. An attacker could
exploit this to steal information from another site. (CVE-2010-3178)

Dmitri GribenkoDmitri Gribenko discovered that Firefox did not properly
setup the LD_LIBRARY_PATH environment variable. A local attacker could
exploit this to execute arbitrary code as the user invoking the program.
(CVE-2010-3182)");

  script_tag(name:"affected", value:"'firefox, firefox-3.0, firefox-3.5, xulrunner-1.9.1, xulrunner-1.9.2' package(s) on Ubuntu 8.04, Ubuntu 9.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
