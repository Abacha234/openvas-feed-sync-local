# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702694");
  script_cve_id("CVE-2013-2118");
  script_tag(name:"creation_date", value:"2013-05-25 22:00:00 +0000 (Sat, 25 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2694)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2694");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2694");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spip' package(s) announced via the DSA-2694 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A privilege escalation vulnerability has been found in SPIP, a website engine for publishing, which allows anyone to take control of the website.

For the oldstable distribution (squeeze), this problem has been fixed in version 2.1.1-3squeeze6.

For the stable distribution (wheezy), this problem has been fixed in version 2.1.17-1+deb7u1.

For the testing distribution (jessie), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 2.1.22-1.

We recommend that you upgrade your spip packages.");

  script_tag(name:"affected", value:"'spip' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);