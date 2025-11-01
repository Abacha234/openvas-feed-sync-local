# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891079");
  script_cve_id("CVE-2017-10788", "CVE-2017-10789");
  script_tag(name:"creation_date", value:"2018-02-06 23:00:00 +0000 (Tue, 06 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 18:24:00 +0000 (Wed, 12 Jul 2017)");

  script_name("Debian: Security Advisory (DLA-1079)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-1079");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1079");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libdbd-mysql-perl' package(s) announced via the DLA-1079 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Perl library for communicating with MySQL database, used in the mysql commandline client is vulnerable to a man in the middle attack in SSL configurations and remote crash when connecting to hostile servers.

CVE-2017-10788

The DBD::mysql module through 4.042 for Perl allows remote attackers to cause a denial of service (use-after-free and application crash) or possibly have unspecified other impact by triggering (1) certain error responses from a MySQL server or (2) a loss of a network connection to a MySQL server. The use-after-free defect was introduced by relying on incorrect Oracle mysql_stmt_close documentation and code examples.

CVE-2017-10789

The DBD::mysql module through 4.042 for Perl uses the mysql_ssl=1 setting to mean that SSL is optional (even though this setting's documentation has a your communication with the server will be encrypted statement), which allows man-in-the-middle attackers to spoof servers via a cleartext-downgrade attack, a related issue to CVE-2015-3152.

For Debian 7 Wheezy, these problems have been fixed in version 4.021-1+deb7u3.

We recommend that you upgrade your libdbd-mysql-perl packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libdbd-mysql-perl' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);