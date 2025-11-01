# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842122");
  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419", "CVE-2014-6585", "CVE-2014-6591", "CVE-2014-7923", "CVE-2014-7926", "CVE-2014-7940", "CVE-2014-9654");
  script_tag(name:"creation_date", value:"2015-03-11 05:40:08 +0000 (Wed, 11 Mar 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2522-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2522-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2522-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icu' package(s) announced via the USN-2522-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2522-1 fixed vulnerabilities in ICU. On Ubuntu 12.04 LTS, the font
patches caused a regression when using LibreOffice Calc. The patches have
now been updated to fix the regression.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that ICU incorrectly handled memory operations when
 processing fonts. If an application using ICU processed crafted data, an
 attacker could cause it to crash or potentially execute arbitrary code with
 the privileges of the user invoking the program. This issue only affected
 Ubuntu 12.04 LTS. (CVE-2013-1569, CVE-2013-2383, CVE-2013-2384,
 CVE-2013-2419)

 It was discovered that ICU incorrectly handled memory operations when
 processing fonts. If an application using ICU processed crafted data, an
 attacker could cause it to crash or potentially execute arbitrary code with
 the privileges of the user invoking the program. (CVE-2014-6585,
 CVE-2014-6591)

 It was discovered that ICU incorrectly handled memory operations when
 processing regular expressions. If an application using ICU processed
 crafted data, an attacker could cause it to crash or potentially execute
 arbitrary code with the privileges of the user invoking the program.
 (CVE-2014-7923, CVE-2014-7926, CVE-2014-9654)

 It was discovered that ICU collator implementation incorrectly handled
 memory operations. If an application using ICU processed crafted data, an
 attacker could cause it to crash or potentially execute arbitrary code with
 the privileges of the user invoking the program. (CVE-2014-7940)");

  script_tag(name:"affected", value:"'icu' package(s) on Ubuntu 12.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
