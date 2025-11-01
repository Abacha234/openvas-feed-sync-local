# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840561");
  script_tag(name:"creation_date", value:"2011-01-11 15:07:49 +0000 (Tue, 11 Jan 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-1036-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1036-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1036-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/690040");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cups' package(s) announced via the USN-1036-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Under certain circumstances, CUPS could start before its AppArmor profile
was loaded and therefore run unconfined. This update ensures the AppArmor
profile is loaded before CUPS starts.");

  script_tag(name:"affected", value:"'cups' package(s) on Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
