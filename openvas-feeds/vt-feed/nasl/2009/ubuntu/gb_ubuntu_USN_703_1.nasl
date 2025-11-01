# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63103");
  script_cve_id("CVE-2006-7236", "CVE-2008-2382", "CVE-2008-2383");
  script_tag(name:"creation_date", value:"2009-01-07 22:16:01 +0000 (Wed, 07 Jan 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-703-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-703-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-703-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xterm' package(s) announced via the USN-703-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Szabo discovered that the DECRQSS escape sequences were not handled
correctly by xterm. Additionally, window title operations were also not
safely handled. If a user were tricked into viewing a specially crafted
series of characters while in xterm, a remote attacker could execute
arbitrary commands with user privileges. (CVE-2006-7236, CVE-2008-2382)");

  script_tag(name:"affected", value:"'xterm' package(s) on Ubuntu 6.06, Ubuntu 7.10, Ubuntu 8.04, Ubuntu 8.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
