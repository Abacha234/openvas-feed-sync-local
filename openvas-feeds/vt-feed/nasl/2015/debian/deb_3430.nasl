# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703430");
  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035", "CVE-2015-8241", "CVE-2015-8317", "CVE-2015-8710");
  script_tag(name:"creation_date", value:"2015-12-22 23:00:00 +0000 (Tue, 22 Dec 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 19:19:00 +0000 (Wed, 26 Feb 2020)");

  script_name("Debian: Security Advisory (DSA-3430)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3430");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3430");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-3430 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in libxml2, a library providing support to read, modify and write XML and HTML files. A remote attacker could provide a specially crafted XML or HTML file that, when processed by an application using libxml2, would cause that application to use an excessive amount of CPU, leak potentially sensitive information, or crash the application.

For the oldstable distribution (wheezy), these problems have been fixed in version 2.8.0+dfsg1-7+wheezy5.

For the stable distribution (jessie), these problems have been fixed in version 2.9.1+dfsg1-5+deb8u1.

For the testing distribution (stretch), these problems have been fixed in version 2.9.3+dfsg1-1 or earlier versions.

For the unstable distribution (sid), these problems have been fixed in version 2.9.3+dfsg1-1 or earlier versions.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);