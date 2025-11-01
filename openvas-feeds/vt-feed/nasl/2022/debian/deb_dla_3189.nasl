# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893189");
  script_tag(name:"creation_date", value:"2022-11-16 02:00:07 +0000 (Wed, 16 Nov 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3189)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3189");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3189");
  script_xref(name:"URL", value:"https://www.postgresql.org/docs/release/11.18");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/postgresql-11");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-11' package(s) announced via the DLA-3189 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several bugs were discovered in PostgreSQL, a relational database server system. This new LTS minor version update fixes over 25 bugs that were reported in the last several months. The complete and detailed list of issues could be found at: [link moved to references].

For Debian 10 buster, this problem has been fixed in version 11.18-0+deb10u1.

We recommend that you upgrade your postgresql-11 packages.

For the detailed security status of postgresql-11 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-11' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);