# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893309");
  script_cve_id("CVE-2022-4728", "CVE-2022-4729", "CVE-2022-4730");
  script_tag(name:"creation_date", value:"2023-02-08 02:00:14 +0000 (Wed, 08 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 18:48:00 +0000 (Thu, 05 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3309");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3309");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphite-web' package(s) announced via the DLA-3309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were a number of issues in graphite-web, a tool provide realtime graphing of system statistics etc.

A series of cross-site scripting (XSS) vulnerabilities existed that could have been exploited remotely. Issues existed in the Cookie Handler, Template Name Handler and Absolute Time Range Handler components:

CVE-2022-4728

A vulnerability classified as problematic has been found in SourceCodester Blood Bank Management System 1.0. Affected is an unknown function of the file index.php?page=users of the component User Registration Handler. The manipulation of the argument Name leads to cross site scripting. It is possible to launch the attack remotely. VDB-216774 is the identifier assigned to this vulnerability.

CVE-2022-4729

A vulnerability classified as critical was found in SourceCodester School Dormitory Management System 1.0. Affected by this vulnerability is an unknown functionality of the component Admin Login. The manipulation leads to sql injection. The attack can be launched remotely. The associated identifier of this vulnerability is VDB-216775.

CVE-2022-4730

A vulnerability was found in Graphite Web. It has been classified as problematic. Affected is an unknown function of the component Absolute Time Range Handler. The manipulation leads to cross site scripting. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. The name of the patch is 2f178f490e10efc03cd1d27c72f64ecab224eb23. It is recommended to apply a patch to fix this issue. The identifier of this vulnerability is VDB-216744.

For Debian 10 Buster, these problems have been fixed in version 1.1.4-3+deb10u2.

We recommend that you upgrade your graphite-web packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'graphite-web' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);