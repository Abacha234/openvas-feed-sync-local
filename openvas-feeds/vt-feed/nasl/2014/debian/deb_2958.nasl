# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702958");
  script_cve_id("CVE-2014-0478");
  script_tag(name:"creation_date", value:"2014-06-11 22:00:00 +0000 (Wed, 11 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2958)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2958");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2958");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DSA-2958 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jakub Wilk discovered that APT, the high level package manager, did not properly perform authentication checks for source packages downloaded via 'apt-get source'. This only affects use cases where source packages are downloaded via this command, it does not affect regular Debian package installation and upgrading.

For the stable distribution (wheezy), this problem has been fixed in version 0.9.7.9+deb7u2.

For the unstable distribution (sid), this problem has been fixed in version 1.0.4.

We recommend that you upgrade your apt packages.");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);