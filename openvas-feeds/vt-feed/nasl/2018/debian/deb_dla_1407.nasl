# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891407");
  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819", "CVE-2018-3081");
  script_tag(name:"creation_date", value:"2018-07-09 22:00:00 +0000 (Mon, 09 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-19 17:02:00 +0000 (Tue, 19 Jul 2022)");

  script_name("Debian: Security Advisory (DLA-1407)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1407");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1407");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10034-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10035-release-notes/");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mariadb-10.0' package(s) announced via the DLA-1407 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MariaDB database server. The vulnerabilities are addressed by upgrading MariaDB to the new upstream version 10.0.35. Please see the MariaDB 10.0 Release Notes for further details:


[link moved to references]

[link moved to references]

For Debian 8 Jessie, these problems have been fixed in version 10.0.35-0+deb8u1.

We recommend that you upgrade your mariadb-10.0 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.0' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);