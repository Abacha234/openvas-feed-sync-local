# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61104");
  script_cve_id("CVE-2008-1105");
  script_tag(name:"creation_date", value:"2008-06-11 16:37:44 +0000 (Wed, 11 Jun 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1590)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1590");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1590");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'samba' package(s) announced via the DSA-1590 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alin Rad Pop discovered that Samba contained a buffer overflow condition when processing certain responses received while acting as a client, leading to arbitrary code execution (CVE-2008-1105).

For the stable distribution (etch), this problem has been fixed in version 3.0.24-6etch10.

For the unstable distribution (sid), this problem has been fixed in version 3.0.30-1.

We recommend that you upgrade your samba packages.");

  script_tag(name:"affected", value:"'samba' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);