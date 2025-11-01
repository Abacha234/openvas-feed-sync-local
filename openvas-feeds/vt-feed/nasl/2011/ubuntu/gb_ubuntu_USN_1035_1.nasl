# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840557");
  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");
  script_tag(name:"creation_date", value:"2011-01-11 15:07:49 +0000 (Tue, 11 Jan 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1035-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1035-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1035-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'evince' package(s) announced via the USN-1035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jon Larimer discovered that Evince's font parsers incorrectly handled
certain buffer lengths when rendering a DVI file. By tricking a user into
opening or previewing a DVI file that uses a specially crafted font file,
an attacker could crash evince or execute arbitrary code with the user's
privileges.

In the default installation of Ubuntu 9.10 and later, attackers would be
isolated by the Evince AppArmor profile.");

  script_tag(name:"affected", value:"'evince' package(s) on Ubuntu 8.04, Ubuntu 9.10, Ubuntu 10.04, Ubuntu 10.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
