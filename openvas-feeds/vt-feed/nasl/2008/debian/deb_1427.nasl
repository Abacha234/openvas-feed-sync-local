# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60006");
  script_cve_id("CVE-2007-6015");
  script_tag(name:"creation_date", value:"2008-01-17 22:23:47 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1427)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1427");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1427");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-1427 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop discovered that Samba, a LanManager-like file and printer server for Unix, is vulnerable to a buffer overflow in the nmbd code which handles GETDC mailslot requests, which might lead to the execution of arbitrary code.

For the old stable distribution (sarge), this problem has been fixed in version 3.0.14a-3sarge11. Packages for m68k will be provided later.

For the stable distribution (etch), this problem has been fixed in version 3.0.24-6etch9.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);