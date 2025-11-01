# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703891");
  script_cve_id("CVE-2017-5664");
  script_tag(name:"creation_date", value:"2017-06-21 22:00:00 +0000 (Wed, 21 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3891)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3891");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3891");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tomcat8' package(s) announced via the DSA-3891 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Aniket Nandkishor Kulkarni discovered that in tomcat8, a servlet and JSP engine, static error pages used the original request's HTTP method to serve content, instead of systematically using the GET method. This could under certain conditions result in undesirable results, including the replacement or removal of the custom error page.

For the oldstable distribution (jessie), this problem has been fixed in version 8.0.14-1+deb8u10.

For the stable distribution (stretch), this problem has been fixed in version 8.5.14-1+deb9u1.

For the testing distribution (buster), this problem has been fixed in version 8.5.14-2.

For the unstable distribution (sid), this problem has been fixed in version 8.5.14-2.

We recommend that you upgrade your tomcat8 packages.");

  script_tag(name:"affected", value:"'tomcat8' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);