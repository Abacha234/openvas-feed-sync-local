# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703530");
  script_cve_id("CVE-2013-4286", "CVE-2013-4322", "CVE-2013-4590", "CVE-2014-0033", "CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119", "CVE-2014-0227", "CVE-2014-0230", "CVE-2014-7810", "CVE-2015-5174", "CVE-2015-5345", "CVE-2015-5346", "CVE-2015-5351", "CVE-2016-0706", "CVE-2016-0714", "CVE-2016-0763");
  script_tag(name:"creation_date", value:"2016-03-24 23:00:00 +0000 (Thu, 24 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-15 16:30:00 +0000 (Mon, 15 Apr 2019)");

  script_name("Debian: Security Advisory (DSA-3530)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3530");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3530");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat6' package(s) announced via the DSA-3530 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been fixed in the Tomcat servlet and JSP engine, which may result on bypass of security manager restrictions, information disclosure, denial of service or session fixation.

For the oldstable distribution (wheezy), these problems have been fixed in version 6.0.45+dfsg-1~deb7u1.

We recommend that you upgrade your tomcat6 packages.");

  script_tag(name:"affected", value:"'tomcat6' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);