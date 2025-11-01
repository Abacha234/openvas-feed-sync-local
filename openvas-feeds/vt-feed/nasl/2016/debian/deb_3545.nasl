# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703545");
  script_cve_id("CVE-2016-1899", "CVE-2016-1900", "CVE-2016-1901");
  script_tag(name:"creation_date", value:"2016-04-06 22:00:00 +0000 (Wed, 06 Apr 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:33:00 +0000 (Wed, 07 Dec 2016)");

  script_name("Debian: Security Advisory (DSA-3545)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3545");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3545");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cgit' package(s) announced via the DSA-3545 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in cgit, a fast web frontend for git repositories written in C. A remote attacker can take advantage of these flaws to perform cross-site scripting, header injection or denial of service attacks.

For the stable distribution (jessie), these problems have been fixed in version 0.10.2.git2.0.1-3+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 0.12.0.git2.7.0-1 or earlier.

For the unstable distribution (sid), these problems have been fixed in version 0.12.0.git2.7.0-1 or earlier.

We recommend that you upgrade your cgit packages.");

  script_tag(name:"affected", value:"'cgit' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);