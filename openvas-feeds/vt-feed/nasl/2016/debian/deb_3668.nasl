# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703668");
  script_cve_id("CVE-2016-6893");
  script_tag(name:"creation_date", value:"2016-09-14 22:00:00 +0000 (Wed, 14 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-13 01:29:00 +0000 (Sun, 13 Aug 2017)");

  script_name("Debian: Security Advisory (DSA-3668)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3668");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3668");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mailman' package(s) announced via the DSA-3668 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a CSRF vulnerability in mailman, a web-based mailing list manager, which could allow an attacker to obtain a user's password.

For the stable distribution (jessie), this problem has been fixed in version 1:2.1.18-2+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 1:2.1.23-1.

We recommend that you upgrade your mailman packages.");

  script_tag(name:"affected", value:"'mailman' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);