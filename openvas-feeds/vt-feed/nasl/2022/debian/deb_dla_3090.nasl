# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893090");
  script_cve_id("CVE-2022-30287");
  script_tag(name:"creation_date", value:"2022-09-01 01:00:12 +0000 (Thu, 01 Sep 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 16:16:00 +0000 (Fri, 05 Aug 2022)");

  script_name("Debian: Security Advisory (DLA-3090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3090");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-3090");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php-horde-turba' package(s) announced via the DLA-3090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an arbitrary object deserialization vulnerability in php-horde-turba, an address book component for the Horde groupware suite.

CVE-2022-30287

Horde Groupware Webmail Edition through 5.2.22 allows a reflection injection attack through which an attacker can instantiate a driver class. This then leads to arbitrary deserialization of PHP objects.

For Debian 10 Buster, these problems have been fixed in version 4.2.23-1+deb10u1.

We recommend that you upgrade your php-horde-turba packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php-horde-turba' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);