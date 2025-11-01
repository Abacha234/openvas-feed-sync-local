# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704559");
  script_cve_id("CVE-2019-18217");
  script_tag(name:"creation_date", value:"2019-11-07 03:00:12 +0000 (Thu, 07 Nov 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-27 21:15:00 +0000 (Sun, 27 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4559)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4559");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4559");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/proftpd-dfsg");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'proftpd-dfsg' package(s) announced via the DSA-4559 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephan Zeisberg discovered that missing input validation in ProFTPD, a FTP/SFTP/FTPS server, could result in denial of service via an infinite loop.

For the oldstable distribution (stretch), this problem has been fixed in version 1.3.5b-4+deb9u2.

For the stable distribution (buster), this problem has been fixed in version 1.3.6-4+deb10u2.

We recommend that you upgrade your proftpd-dfsg packages.

For the detailed security status of proftpd-dfsg please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'proftpd-dfsg' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);