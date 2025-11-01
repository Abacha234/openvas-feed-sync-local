# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703057");
  script_cve_id("CVE-2014-3660");
  script_tag(name:"creation_date", value:"2014-10-25 22:00:00 +0000 (Sat, 25 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3057)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3057");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3057");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxml2' package(s) announced via the DSA-3057 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sogeti found a denial of service flaw in libxml2, a library providing support to read, modify and write XML and HTML files. A remote attacker could provide a specially crafted XML file that, when processed by an application using libxml2, would lead to excessive CPU consumption (denial of service) based on excessive entity substitutions, even if entity substitution was disabled, which is the parser default behavior. (CVE-2014-3660)

In addition, this update addresses a misapplied chunk for a patch released in version 2.8.0+dfsg1-7+wheezy1 (#762864), and a memory leak regression (#765770) introduced in version 2.8.0+dfsg1-7+nmu3.

For the stable distribution (wheezy), this problem has been fixed in version 2.8.0+dfsg1-7+wheezy2.

For the unstable distribution (sid), this problem has been fixed in version 2.9.2+dfsg1-1.

We recommend that you upgrade your libxml2 packages.");

  script_tag(name:"affected", value:"'libxml2' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);