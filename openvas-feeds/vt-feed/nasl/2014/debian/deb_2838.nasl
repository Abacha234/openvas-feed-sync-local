# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702838");
  script_cve_id("CVE-2013-6462");
  script_tag(name:"creation_date", value:"2014-01-06 23:00:00 +0000 (Mon, 06 Jan 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2838)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2838");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2838");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxfont' package(s) announced via the DSA-2838 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a buffer overflow in the processing of Glyph Bitmap Distribution fonts (BDF) could result in the execution of arbitrary code.

For the oldstable distribution (squeeze), this problem has been fixed in version 1:1.4.1-4.

For the stable distribution (wheezy), this problem has been fixed in version 1:1.4.5-3.

For the unstable distribution (sid), this problem has been fixed in version 1:1.4.7-1.

We recommend that you upgrade your libxfont packages.");

  script_tag(name:"affected", value:"'libxfont' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);