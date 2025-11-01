# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704168");
  script_cve_id("CVE-2018-8741");
  script_tag(name:"creation_date", value:"2018-04-07 22:00:00 +0000 (Sat, 07 Apr 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-15 20:15:00 +0000 (Thu, 15 Aug 2019)");

  script_name("Debian: Security Advisory (DSA-4168)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4168");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4168");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/squirrelmail");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'squirrelmail' package(s) announced via the DSA-4168 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Grunow and Birk Kauer of ERNW discovered a path traversal vulnerability in SquirrelMail, a webmail application, allowing an authenticated remote attacker to retrieve or delete arbitrary files via mail attachment.

For the oldstable distribution (jessie), this problem has been fixed in version 2:1.4.23~svn20120406-2+deb8u2.

We recommend that you upgrade your squirrelmail packages.

For the detailed security status of squirrelmail please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'squirrelmail' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);