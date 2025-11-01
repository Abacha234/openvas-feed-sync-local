# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840458");
  script_cve_id("CVE-2010-0832");
  script_tag(name:"creation_date", value:"2010-07-12 09:56:20 +0000 (Mon, 12 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-959-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-959-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-959-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam' package(s) announced via the USN-959-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Denis Excoffier discovered that the PAM MOTD module in Ubuntu did
not correctly handle path permissions when creating user file stamps.
A local attacker could exploit this to gain root privilieges.");

  script_tag(name:"affected", value:"'pam' package(s) on Ubuntu 9.10, Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
