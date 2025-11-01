# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703369");
  script_cve_id("CVE-2015-5723", "CVE-2015-7695");
  script_tag(name:"creation_date", value:"2015-10-05 22:00:00 +0000 (Mon, 05 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-28 19:44:00 +0000 (Mon, 28 Nov 2016)");

  script_name("Debian: Security Advisory (DSA-3369)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3369");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3369");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'zendframework' package(s) announced via the DSA-3369 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in Zend Framework, a PHP framework:

CVE-2015-5723

It was discovered that due to incorrect permissions masks when creating directories, local attackers could potentially execute arbitrary code or escalate privileges.

ZF2015-08 (no CVE assigned) Chris Kings-Lynne discovered an SQL injection vector caused by missing null byte filtering in the MS SQL PDO backend, and a similar issue was also found in the SQLite backend.

For the oldstable distribution (wheezy), this problem has been fixed in version 1.11.13-1.1+deb7u4.

For the stable distribution (jessie), this problem has been fixed in version 1.12.9+dfsg-2+deb8u4.

For the testing distribution (stretch), this problem has been fixed in version 1.12.16+dfsg-1.

For the unstable distribution (sid), this problem has been fixed in version 1.12.16+dfsg-1.

We recommend that you upgrade your zendframework packages.");

  script_tag(name:"affected", value:"'zendframework' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);