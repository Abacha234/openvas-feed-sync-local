# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842437");
  script_cve_id("CVE-2015-1270", "CVE-2015-2632", "CVE-2015-4760");
  script_tag(name:"creation_date", value:"2015-09-17 04:18:53 +0000 (Thu, 17 Sep 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2740-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2740-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2740-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the USN-2740-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Atte Kettunen discovered that ICU incorrectly handled certain converter
names. If an application using ICU processed crafted data, a remote
attacker could possibly cause it to crash. (CVE-2015-1270)

It was discovered that ICU incorrectly handled certain memory operations
when processing data. If an application using ICU processed crafted data,
a remote attacker could possibly cause it to crash or potentially execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2015-2632, CVE-2015-4760)");

  script_tag(name:"affected", value:"'icu' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
