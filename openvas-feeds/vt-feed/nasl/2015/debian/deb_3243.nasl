# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703243");
  script_cve_id("CVE-2015-3451");
  script_tag(name:"creation_date", value:"2015-04-30 22:00:00 +0000 (Thu, 30 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3243)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3243");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3243");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml-libxml-perl' package(s) announced via the DSA-3243 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tilmann Haak from xing.com discovered that XML::LibXML, a Perl interface to the libxml2 library, did not respect the expand_entities parameter to disable processing of external entities in some circumstances. This may allow attackers to gain read access to otherwise protected resources, depending on how the library is used.

For the oldstable distribution (wheezy), this problem has been fixed in version 2.0001+dfsg-1+deb7u1.

For the stable distribution (jessie), this problem has been fixed in version 2.0116+dfsg-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.0116+dfsg-2.

We recommend that you upgrade your libxml-libxml-perl packages.");

  script_tag(name:"affected", value:"'libxml-libxml-perl' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);