# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703518");
  script_cve_id("CVE-2016-3153", "CVE-2016-3154");
  script_tag(name:"creation_date", value:"2016-03-15 23:00:00 +0000 (Tue, 15 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 21:49:00 +0000 (Thu, 14 Apr 2016)");

  script_name("Debian: Security Advisory (DSA-3518)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3518");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3518");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'spip' package(s) announced via the DSA-3518 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in SPIP, a website engine for publishing, resulting in code injection.

CVE-2016-3153

g0uZ et sambecks, from team root-me, discovered that arbitrary PHP code could be injected when adding content.

CVE-2016-3154

Gilles Vincent discovered that deserializing untrusted content could result in arbitrary objects injection.

For the oldstable distribution (wheezy), these problems have been fixed in version 2.1.17-1+deb7u5.

For the stable distribution (jessie), these problems have been fixed in version 3.0.17-2+deb8u2.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 3.0.22-1.

We recommend that you upgrade your spip packages.");

  script_tag(name:"affected", value:"'spip' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);