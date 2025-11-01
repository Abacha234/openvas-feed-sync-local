# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892041");
  script_cve_id("CVE-2019-3467");
  script_tag(name:"creation_date", value:"2019-12-19 03:00:07 +0000 (Thu, 19 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-25 00:15:00 +0000 (Fri, 25 Sep 2020)");

  script_name("Debian: Security Advisory (DLA-2041)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2041");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/dla-2041");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'debian-edu-config' package(s) announced via the DLA-2041 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that debian-edu-config, the package containing the configuration files and scripts for Debian Edu (Skolelinux), contained an insecure configuration for kadmin, the Kerberos administration server. The insecure configuration allowed every user to change other users' passwords, thus impersonating them and possibly gaining their privileges.

The bug was not exposed in the officially documented user management frontends of Debian Edu, but could be abused by local network users knowing how to use the Kerberos backend.

For Debian 8 Jessie, this problem has been fixed in version 1.818+deb8u3.

We recommend that you upgrade your debian-edu-config packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'debian-edu-config' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);