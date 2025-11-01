# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704071");
  script_cve_id("CVE-2017-17512");
  script_tag(name:"creation_date", value:"2017-12-20 23:00:00 +0000 (Wed, 20 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)");

  script_name("Debian: Security Advisory (DSA-4071)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4071");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4071");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sensible-utils");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sensible-utils' package(s) announced via the DSA-4071 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gabriel Corona reported that sensible-browser from sensible-utils, a collection of small utilities used to sensibly select and spawn an appropriate browser, editor or pager, does not validate strings before launching the program specified by the BROWSER environment variable, potentially allowing a remote attacker to conduct argument-injection attacks if a user is tricked into processing a specially crafted URL.

For the oldstable distribution (jessie), this problem has been fixed in version 0.0.9+deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 0.0.9+deb9u1.

We recommend that you upgrade your sensible-utils packages.

For the detailed security status of sensible-utils please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'sensible-utils' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);