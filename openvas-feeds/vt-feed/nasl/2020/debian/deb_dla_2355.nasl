# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892355");
  script_cve_id("CVE-2020-8622", "CVE-2020-8623");
  script_tag(name:"creation_date", value:"2020-08-30 03:00:36 +0000 (Sun, 30 Aug 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-2355)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2355");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2020/dla-2355");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/bind9");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'bind9' package(s) announced via the DLA-2355 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been found in bind9, an Internet Domain Name Server.

CVE-2020-8622

Crafted responses to TSIG-signed requests could lead to an assertion failure, causing the server to exit. This could be done by malicious server operators or guessing attackers.

CVE-2020-8623

An assertions failure, causing the server to exit, can be exploited by a query for an RSA signed zone.

For Debian 9 stretch, these problems have been fixed in version 1:9.10.3.dfsg.P4-12.3+deb9u7.

We recommend that you upgrade your bind9 packages.

For the detailed security status of bind9 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'bind9' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);