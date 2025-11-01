# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705136");
  script_cve_id("CVE-2022-1552");
  script_tag(name:"creation_date", value:"2022-05-13 01:00:12 +0000 (Fri, 13 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-07 20:04:00 +0000 (Wed, 07 Sep 2022)");

  script_name("Debian: Security Advisory (DSA-5136)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5136");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5136");
  script_xref(name:"URL", value:"https://www.postgresql.org/support/security/CVE-2022-1552//");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/postgresql-13");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postgresql-13' package(s) announced via the DSA-5136 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexander Lakhin discovered that the autovacuum feature and multiple commands could escape the 'security-restricted operation' sandbox.

For additional information please refer to the upstream announcement at [link moved to references]

For the stable distribution (bullseye), this problem has been fixed in version 13.7-0+deb11u1.

We recommend that you upgrade your postgresql-13 packages.

For the detailed security status of postgresql-13 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'postgresql-13' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);