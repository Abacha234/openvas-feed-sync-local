# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704573");
  script_cve_id("CVE-2019-18887", "CVE-2019-18888");
  script_tag(name:"creation_date", value:"2019-11-20 03:00:09 +0000 (Wed, 20 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Debian: Security Advisory (DSA-4573)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4573");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4573");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/symfony");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-4573 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the Symfony PHP framework which could lead to a timing attack/information leak, argument injection and code execution via unserialization.

For the oldstable distribution (stretch), these problems have been fixed in version 2.8.7+dfsg-1.3+deb9u3.

For the stable distribution (buster), these problems have been fixed in version 3.4.22+dfsg-2+deb10u1.

We recommend that you upgrade your symfony packages.

For the detailed security status of symfony please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);