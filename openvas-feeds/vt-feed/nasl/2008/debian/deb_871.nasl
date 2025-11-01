# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55746");
  script_cve_id("CVE-2005-2958");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-871)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-871");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/dsa-871");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libgda2' package(s) announced via the DSA-871 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Steve Kemp discovered two format string vulnerabilities in libgda2, the GNOME Data Access library for GNOME2, which may lead to the execution of arbitrary code in programs that use this library.

The old stable distribution (woody) is not affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 1.2.1-2sarge1.

For the unstable distribution (sid) these problems will be fixed soon.

We recommend that you upgrade your libgda2 packages.");

  script_tag(name:"affected", value:"'libgda2' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);