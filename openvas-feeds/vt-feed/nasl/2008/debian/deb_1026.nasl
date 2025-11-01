# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.56537");
  script_cve_id("CVE-2005-1849", "CVE-2005-2096");
  script_tag(name:"creation_date", value:"2008-01-17 22:09:45 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1026");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1026");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sash' package(s) announced via the DSA-1026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Markus Oberhumer discovered a flaw in the way zlib, a library used for file compression and decompression, handles invalid input. This flaw can cause programs which use zlib to crash when opening an invalid file. A further error in the way zlib handles the inflation of certain compressed files can cause a program which uses zlib to crash when opening an invalid file.

sash, the stand-alone shell, links statically against zlib, and was thus affected by these problems.

The old stable distribution (woody) isn't affected by these problems.

For the stable distribution (sarge) these problems have been fixed in version 3.7-5sarge1.

For the unstable distribution (sid) these problems have been fixed in version 3.7-6.

We recommend that you upgrade your sash package.");

  script_tag(name:"affected", value:"'sash' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);