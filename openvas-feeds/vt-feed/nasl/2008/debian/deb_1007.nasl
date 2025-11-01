# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56458");
  script_cve_id("CVE-2006-1225", "CVE-2006-1226", "CVE-2006-1227", "CVE-2006-1228");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1007)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1007");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1007");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'drupal' package(s) announced via the DSA-1007 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Drupal Security Team discovered several vulnerabilities in Drupal, a fully-featured content management and discussion engine. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-1225

Due to missing input sanitising a remote attacker could inject headers of outgoing e-mail messages and use Drupal as a spam proxy.

CVE-2006-1226

Missing input sanity checks allows attackers to inject arbitrary web script or HTML.

CVE-2006-1227

Menu items created with the menu.module lacked access control, which might allow remote attackers to access administrator pages.

CVE-2006-1228

Markus Petrux discovered a bug in the session fixation which may allow remote attackers to gain Drupal user privileges.

The old stable distribution (woody) does not contain Drupal packages.

For the stable distribution (sarge) these problems have been fixed in version 4.5.3-6.

For the unstable distribution (sid) these problems have been fixed in version 4.5.8-1.

We recommend that you upgrade your drupal package.");

  script_tag(name:"affected", value:"'drupal' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);