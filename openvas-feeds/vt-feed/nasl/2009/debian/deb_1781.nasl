# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63934");
  script_cve_id("CVE-2008-3162", "CVE-2009-0385");
  script_tag(name:"creation_date", value:"2009-05-05 14:00:35 +0000 (Tue, 05 May 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1781)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1781");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1781");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg, ffmpeg-debian' package(s) announced via the DSA-1781 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in ffmpeg, a multimedia player, server and encoder. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0385

It was discovered that watching a malformed 4X movie file could lead to the execution of arbitrary code.

CVE-2008-3162

It was discovered that using a crafted STR file can lead to the execution of arbitrary code.

For the oldstable distribution (etch), these problems have been fixed in version 0.cvs20060823-8+etch1.

For the stable distribution (lenny), these problems have been fixed in version 0.svn20080206-17+lenny1.

For the testing distribution (squeeze) and the unstable distribution (sid), these problems have been fixed in version 0.svn20080206-16.

We recommend that you upgrade your ffmpeg-debian packages.");

  script_tag(name:"affected", value:"'ffmpeg, ffmpeg-debian' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);