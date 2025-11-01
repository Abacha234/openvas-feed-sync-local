# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702652");
  script_cve_id("CVE-2013-0338", "CVE-2013-0339");
  script_tag(name:"creation_date", value:"2013-03-23 23:00:00 +0000 (Sat, 23 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2652)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2652");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2652");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-2652 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Brad Hill of iSEC Partners discovered that many XML implementations are vulnerable to external entity expansion issues, which can be used for various purposes such as firewall circumvention, disguising an IP address, and denial-of-service. libxml2 was susceptible to these problems when performing string substitution during entity expansion.

For the stable distribution (squeeze), these problems have been fixed in version 2.7.8.dfsg-2+squeeze7.

For the testing (wheezy) and unstable (sid) distributions, these problems have been fixed in version 2.8.0+dfsg1-7+nmu1.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);