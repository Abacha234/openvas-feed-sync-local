# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704262");
  script_cve_id("CVE-2016-2403", "CVE-2017-16652", "CVE-2017-16653", "CVE-2017-16654", "CVE-2017-16790", "CVE-2018-11385", "CVE-2018-11386", "CVE-2018-11406");
  script_tag(name:"creation_date", value:"2018-08-02 22:00:00 +0000 (Thu, 02 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-06 01:29:00 +0000 (Mon, 06 Aug 2018)");

  script_name("Debian: Security Advisory (DSA-4262)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4262");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4262");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/symfony");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'symfony' package(s) announced via the DSA-4262 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in the Symfony PHP framework which could lead to open redirects, cross-site request forgery, information disclosure, session fixation or denial of service.

For the stable distribution (stretch), these problems have been fixed in version 2.8.7+dfsg-1.3+deb9u1.

We recommend that you upgrade your symfony packages.

For the detailed security status of symfony please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'symfony' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);