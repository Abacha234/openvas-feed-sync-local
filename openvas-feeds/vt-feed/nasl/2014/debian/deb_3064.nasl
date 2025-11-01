# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703064");
  script_cve_id("CVE-2013-7345", "CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670");
  script_tag(name:"creation_date", value:"2014-11-03 23:00:00 +0000 (Mon, 03 Nov 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3064)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3064");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3064");
  script_xref(name:"URL", value:"http://php.net/ChangeLog-5.php#5.4.34");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3064 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in PHP, a general-purpose scripting language commonly used for web application development. It has been decided to follow the stable 5.4.x releases for the Wheezy PHP packages. Consequently the vulnerabilities are addressed by upgrading PHP to a new upstream version 5.4.34, which includes additional bug fixes, new features and possibly incompatible changes. Please refer to the upstream changelog for more information:

[link moved to references]

For the stable distribution (wheezy), these problems have been fixed in version 5.4.34-0+deb7u1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);