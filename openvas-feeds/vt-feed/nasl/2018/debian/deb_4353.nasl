# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704353");
  script_cve_id("CVE-2018-14851", "CVE-2018-14883", "CVE-2018-17082", "CVE-2018-19518", "CVE-2018-19935", "CVE-2018-20783");
  script_tag(name:"creation_date", value:"2018-12-09 23:00:00 +0000 (Sun, 09 Dec 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-18 18:12:00 +0000 (Mon, 18 Apr 2022)");

  script_name("Debian: Security Advisory (DSA-4353)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4353");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4353");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.0' package(s) announced via the DSA-4353 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in PHP, a widely-used open source general purpose scripting language: The EXIF module was susceptible to denial of service/information disclosure when parsing malformed images, the Apache module allowed cross-site-scripting via the body of a 'Transfer-Encoding: chunked' request and the IMAP extension performed insufficient input validation which can result in the execution of arbitrary shell commands in the imap_open() function and denial of service in the imap_mail() function.

For the stable distribution (stretch), these problems have been fixed in version 7.0.33-0+deb9u1.

We recommend that you upgrade your php7.0 packages.

For the detailed security status of php7.0 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.0' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);