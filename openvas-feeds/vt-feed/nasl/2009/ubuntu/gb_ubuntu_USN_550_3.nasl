# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840154");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-550-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-550-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-550-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/175573");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcairo' package(s) announced via the USN-550-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-550-1 fixed vulnerabilities in Cairo. A bug in font glyph rendering
was uncovered as a result of the new memory allocation routines. In
certain situations, fonts containing characters with no width or height
would not render any more. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Peter Valchev discovered that Cairo did not correctly decode PNG image data.
 By tricking a user or automated system into processing a specially crafted
 PNG with Cairo, a remote attacker could execute arbitrary code with user
 privileges.");

  script_tag(name:"affected", value:"'libcairo' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
