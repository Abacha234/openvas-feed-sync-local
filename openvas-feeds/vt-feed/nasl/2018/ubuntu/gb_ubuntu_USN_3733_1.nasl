# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843608");
  script_cve_id("CVE-2017-7526");
  script_tag(name:"creation_date", value:"2018-08-08 03:50:54 +0000 (Wed, 08 Aug 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:29:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3733-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3733-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3733-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1785176");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnupg' package(s) announced via the USN-3733-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel J. Bernstein, Joachim Breitner, Daniel Genkin, Leon Groot Bruinderink,
Nadia Heninger, Tanja Lange, Christine van Vredendaal, and Yuval Yarom
discovered that GnuPG is vulnerable to a cache side-channel attack. A local
attacker could use this attack to recover RSA private keys.");

  script_tag(name:"affected", value:"'gnupg' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
