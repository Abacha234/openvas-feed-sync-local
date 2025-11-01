# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704341");
  script_cve_id("CVE-2017-10268", "CVE-2017-10378", "CVE-2017-15365", "CVE-2018-2562", "CVE-2018-2612", "CVE-2018-2622", "CVE-2018-2640", "CVE-2018-2665", "CVE-2018-2668", "CVE-2018-2755", "CVE-2018-2761", "CVE-2018-2766", "CVE-2018-2767", "CVE-2018-2771", "CVE-2018-2781", "CVE-2018-2782", "CVE-2018-2784", "CVE-2018-2787", "CVE-2018-2813", "CVE-2018-2817", "CVE-2018-2819", "CVE-2018-3058", "CVE-2018-3063", "CVE-2018-3064", "CVE-2018-3066", "CVE-2018-3081", "CVE-2018-3143", "CVE-2018-3156", "CVE-2018-3174", "CVE-2018-3251", "CVE-2018-3282", "CVE-2019-2503");
  script_tag(name:"creation_date", value:"2018-11-18 23:00:00 +0000 (Sun, 18 Nov 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-01 14:12:00 +0000 (Fri, 01 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-4341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4341");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4341");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10127-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10128-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10129-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10130-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10131-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10132-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10133-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10134-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10135-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10136-release-notes/");
  script_xref(name:"URL", value:"https://mariadb.com/kb/en/mariadb/mariadb-10137-release-notes/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mariadb-10.1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mariadb-10.1' package(s) announced via the DSA-4341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been discovered in the MariaDB database server. The vulnerabilities are addressed by upgrading MariaDB to the new upstream version 10.1.37. Please see the MariaDB 10.1 Release Notes for further details:

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

[link moved to references]

For the stable distribution (stretch), these problems have been fixed in version 10.1.37-0+deb9u1.

We recommend that you upgrade your mariadb-10.1 packages.

For the detailed security status of mariadb-10.1 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mariadb-10.1' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);