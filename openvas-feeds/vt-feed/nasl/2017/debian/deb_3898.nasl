# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703898");
  script_cve_id("CVE-2017-9233");
  script_tag(name:"creation_date", value:"2017-06-24 22:00:00 +0000 (Sat, 24 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 11:30:00 +0000 (Thu, 28 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-3898)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3898");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3898");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'expat' package(s) announced via the DSA-3898 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Expat, an XML parsing C library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2016-9063

Gustavo Grieco discovered an integer overflow flaw during parsing of XML. An attacker can take advantage of this flaw to cause a denial of service against an application using the Expat library.

CVE-2017-9233

Rhodri James discovered an infinite loop vulnerability within the entityValueInitProcessor() function while parsing malformed XML in an external entity. An attacker can take advantage of this flaw to cause a denial of service against an application using the Expat library.

For the oldstable distribution (jessie), these problems have been fixed in version 2.1.0-6+deb8u4.

For the stable distribution (stretch), these problems have been fixed in version 2.2.0-2+deb9u1. For the stable distribution (stretch), CVE-2016-9063 was already fixed before the initial release.

For the testing distribution (buster), these problems have been fixed in version 2.2.1-1 or earlier version.

For the unstable distribution (sid), these problems have been fixed in version 2.2.1-1 or earlier version.

We recommend that you upgrade your expat packages.");

  script_tag(name:"affected", value:"'expat' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);