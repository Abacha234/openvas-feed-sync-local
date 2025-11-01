# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53718");
  script_cve_id("CVE-2004-1025", "CVE-2004-1026");
  script_tag(name:"creation_date", value:"2008-01-17 21:56:38 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-618)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-618");
  script_xref(name:"URL", value:"https://www.debian.org/security/2004/dsa-618");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'imlib' package(s) announced via the DSA-618 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pavel Kankovsky discovered that several overflows found in the libXpm library were also present in imlib, an imaging library for X and X11. An attacker could create a carefully crafted image file in such a way that it could cause an application linked with imlib to execute arbitrary code when the file was opened by a victim. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2004-1025

Multiple heap-based buffer overflows.

CAN-2004-1026

Multiple integer overflows.

For the stable distribution (woody) these problems have been fixed in version 1.9.14-2woody2.

For the unstable distribution (sid) these problems have been fixed in version 1.9.14-17.1 of imlib and in version 1.9.14-16.1 of imlib+png2 which produces the imlib1 package.

We recommend that you upgrade your imlib packages immediately.");

  script_tag(name:"affected", value:"'imlib' package(s) on Debian 3.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);