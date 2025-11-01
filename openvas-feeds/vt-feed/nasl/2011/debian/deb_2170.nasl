# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69104");
  script_cve_id("CVE-2010-3089", "CVE-2011-0707");
  script_tag(name:"creation_date", value:"2011-03-09 04:54:11 +0000 (Wed, 09 Mar 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2170");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2170");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mailman' package(s) announced via the DSA-2170 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two cross site scripting vulnerabilities were been discovered in Mailman, a web-based mailing list manager. These allowed an attacker to retrieve session cookies via inserting crafted JavaScript into confirmation messages (CVE-2011-0707) and in the list admin interface (CVE-2010-3089, oldstable only).

For the oldstable distribution (lenny), these problems have been fixed in version 1:2.1.11-11+lenny2.

For the stable distribution (squeeze), this problem has been fixed in version 1:2.1.13-5.

For the testing (wheezy) and unstable distribution (sid), this problem has been fixed in version 1:2.1.14-1.

We recommend that you upgrade your mailman packages.");

  script_tag(name:"affected", value:"'mailman' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);