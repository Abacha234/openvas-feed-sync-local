# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55259");
  script_cve_id("CVE-2005-2088");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-803)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-803");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-803");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apache' package(s) announced via the DSA-803 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been discovered in the Apache web server. When it is acting as an HTTP proxy, it allows remote attackers to poison the web cache, bypass web application firewall protection, and conduct cross-site scripting attacks, which causes Apache to incorrectly handle and forward the body of the request.

The fix for this bug is contained in the apache-common package which means that there isn't any need for a separate update of the apache-perl and apache-ssl package.

For the old stable distribution (woody) this problem has been fixed in version 1.3.26-0woody7.

For the stable distribution (sarge) this problem has been fixed in version 1.3.33-6sarge1.

For the unstable distribution (sid) this problem has been fixed in version 1.3.33-8.

We recommend that you upgrade your Apache package.");

  script_tag(name:"affected", value:"'apache' package(s) on Debian 3.0, Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);