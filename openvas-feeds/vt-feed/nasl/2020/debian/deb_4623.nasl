# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704623");
  script_cve_id("CVE-2020-1720");
  script_tag(name:"creation_date", value:"2020-02-15 04:00:10 +0000 (Sat, 15 Feb 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-15 13:28:00 +0000 (Thu, 15 Oct 2020)");

  script_name("Debian: Security Advisory (DSA-4623)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4623");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4623");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/postgresql-11");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-11' package(s) announced via the DSA-4623 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tom Lane discovered that ALTER ... DEPENDS ON EXTENSION sub commands in the PostgreSQL database did not perform authorisation checks.

For the stable distribution (buster), this problem has been fixed in version 11.7-0+deb10u1.

We recommend that you upgrade your postgresql-11 packages.

For the detailed security status of postgresql-11 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-11' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);