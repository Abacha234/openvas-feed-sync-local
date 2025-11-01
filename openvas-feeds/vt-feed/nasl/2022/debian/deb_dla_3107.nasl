# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893107");
  script_cve_id("CVE-2020-35525", "CVE-2020-35527");
  script_tag(name:"creation_date", value:"2022-09-14 01:00:12 +0000 (Wed, 14 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 17:47:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Debian: Security Advisory (DLA-3107)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3107");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3107");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sqlite3' package(s) announced via the DLA-3107 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three issues were discovered in SQLite, a popular embedded database:

CVE-2020-35525: Prevent a potential null pointer deference issue in INTERSEC query processing.

CVE-2020-35527: Prevent an out-of-bounds access issue that could be exploited via ALTER TABLE in views that have a nested FROM clauses.

For Debian 10 Buster, these problems have been fixed in version 3.27.2-3+deb10u2.

We recommend that you upgrade your sqlite3 packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);