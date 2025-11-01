# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66772");
  script_cve_id("CVE-2009-4414", "CVE-2009-4415", "CVE-2009-4416");
  script_tag(name:"creation_date", value:"2010-02-01 17:25:19 +0000 (Mon, 01 Feb 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1978)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1978");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-1978");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpgroupware' package(s) announced via the DSA-1978 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpgroupware, a Web based groupware system written in PHP. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-4414

An SQL injection vulnerability was found in the authentication module.

CVE-2009-4415

Multiple directory traversal vulnerabilities were found in the addressbook module.

CVE-2009-4416

The authentication module is affected by cross-site scripting.

For the stable distribution (lenny) these problems have been fixed in version 0.9.16.012+dfsg-8+lenny1.

For the unstable distribution (sid) these problems have been fixed in version 0.9.16.012+dfsg-9.

We recommend that you upgrade your phpgroupware packages.");

  script_tag(name:"affected", value:"'phpgroupware' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);