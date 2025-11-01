# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61593");
  script_cve_id("CVE-2008-1806", "CVE-2008-1807", "CVE-2008-1808");
  script_tag(name:"creation_date", value:"2008-09-17 02:23:15 +0000 (Wed, 17 Sep 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1635)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1635");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1635");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'freetype' package(s) announced via the DSA-1635 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in freetype, a FreeType 2 font engine, which could allow the execution of arbitrary code.

The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-1806

An integer overflow allows context-dependent attackers to execute arbitrary code via a crafted set of values within the Private dictionary table in a Printer Font Binary (PFB) file.

CVE-2008-1807

The handling of an invalid number of axes field in the PFB file could trigger the freeing of arbitrary memory locations, leading to memory corruption.

CVE-2008-1808

Multiple off-by-one errors allowed the execution of arbitrary code via malformed tables in PFB files, or invalid SHC instructions in TTF files.

For the stable distribution (etch), these problems have been fixed in version 2.2.1-5+etch3.

For the unstable distribution (sid), these problems have been fixed in version 2.3.6-1.

We recommend that you upgrade your freetype package.");

  script_tag(name:"affected", value:"'freetype' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);