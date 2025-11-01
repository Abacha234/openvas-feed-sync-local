# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704640");
  script_cve_id("CVE-2019-19950", "CVE-2019-19951", "CVE-2019-19953");
  script_tag(name:"creation_date", value:"2020-03-18 10:45:19 +0000 (Wed, 18 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-15 01:15:00 +0000 (Wed, 15 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-4640)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4640");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4640");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/graphicsmagick");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DSA-4640 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes several vulnerabilities in Graphicsmagick: Various memory handling problems and cases of missing or incomplete input sanitising may result in denial of service, memory disclosure or the execution of arbitrary code if malformed media files are processed.

For the oldstable distribution (stretch), these problems have been fixed in version 1.3.30+hg15796-1~deb9u3.

For the stable distribution (buster), these problems have been fixed in version 1.4~hg15978-1+deb10u1.

We recommend that you upgrade your graphicsmagick packages.

For the detailed security status of graphicsmagick please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);