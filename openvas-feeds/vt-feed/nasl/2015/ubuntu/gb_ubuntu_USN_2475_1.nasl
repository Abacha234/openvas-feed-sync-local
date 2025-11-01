# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842041");
  script_tag(name:"creation_date", value:"2015-01-23 11:57:55 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-2475-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2475-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2475-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1366790");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk+3.0' package(s) announced via the USN-2475-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Clemens Fries discovered that GTK+ allowed bypassing certain screen locks
by using the menu key. An attacker with physical access could possibly use
this flaw to gain access to a locked session.");

  script_tag(name:"affected", value:"'gtk+3.0' package(s) on Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
