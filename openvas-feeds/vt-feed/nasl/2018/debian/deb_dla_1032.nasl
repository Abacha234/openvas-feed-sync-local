# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891032");
  script_tag(name:"creation_date", value:"2018-02-07 23:00:00 +0000 (Wed, 07 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-1032)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1032");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1032");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'unattended-upgrades' package(s) announced via the DLA-1032 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Since the release of the last Debian stable release ('stretch'), Debian LTS ('wheezy') has been renamed oldoldstable, which broke the unattended-upgrades package as described in bug #867169. Updates would simply not be performed anymore.

For Debian 7 Wheezy, these problems have been fixed in version 0.79.5+wheezy3. Note that later unattended-upgrades version released in later Debian versions do not exhibit the same behavior, as they use the release codename (e.g. jessie) instead of the suite name (e.g. oldstable) in the configuration file. So later releases will transition correctly for future LTS releases.

We recommend that you upgrade your unattended-upgrades packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'unattended-upgrades' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);