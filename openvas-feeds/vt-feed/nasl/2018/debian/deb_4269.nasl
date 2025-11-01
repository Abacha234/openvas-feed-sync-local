# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704269");
  script_cve_id("CVE-2018-10915", "CVE-2018-10925");
  script_tag(name:"creation_date", value:"2018-08-09 22:00:00 +0000 (Thu, 09 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:38:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Debian: Security Advisory (DSA-4269)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4269");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4269");
  script_xref(name:"URL", value:"https://www.postgresql.org/about/news/1878/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/postgresql-9.6");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-9.6' package(s) announced via the DSA-4269 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been found in the PostgreSQL database system:

CVE-2018-10915

Andrew Krasichkov discovered that libpq did not reset all its connection state during reconnects.

CVE-2018-10925

It was discovered that some CREATE TABLE statements could disclose server memory.

For additional information please refer to the upstream announcement at [link moved to references]

For the stable distribution (stretch), these problems have been fixed in version 9.6.10-0+deb9u1.

We recommend that you upgrade your postgresql-9.6 packages.

For the detailed security status of postgresql-9.6 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-9.6' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);