# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58453");
  script_cve_id("CVE-2007-3316", "CVE-2007-3467", "CVE-2007-3468");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1332)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1332");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1332");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'vlc' package(s) announced via the DSA-1332 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the VideoLan multimedia player and streamer, which may lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-3316

David Thiel discovered that several format string vulnerabilities may lead to the execution of arbitrary code.

CVE-2007-3467

David Thiel discovered an integer overflow in the WAV processing code.

This update also fixes several crashes, which can be triggered through malformed media files.

For the oldstable distribution (sarge) these problems have been fixed in version 0.8.1.svn20050314-1sarge3. Packages for the powerpc architecture are not yet available. They will be provided later.

For the stable distribution (etch) these problems have been fixed in version 0.8.6-svn20061012.debian-5etch1.

For the unstable distribution (sid) these problems have been fixed in version 0.8.6.c-1.

We recommend that you upgrade your vlc packages.");

  script_tag(name:"affected", value:"'vlc' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);