# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67835");
  script_cve_id("CVE-2007-6725", "CVE-2008-3522", "CVE-2008-6679", "CVE-2009-0196", "CVE-2009-0792", "CVE-2009-4270", "CVE-2010-1869");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2080)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2080");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2080");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ghostscript' package(s) announced via the DSA-2080 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been discovered in Ghostscript, a GPL PostScript/PDF interpreter, which might lead to the execution of arbitrary code if a user processes a malformed PDF or Postscript file.

For the stable distribution (lenny), these problems have been fixed in version 8.62.dfsg.1-3.2lenny4.

For the unstable distribution (sid), these problems have been fixed in version 8.71~dfsg-4.

We recommend that you upgrade your ghostscript packages.");

  script_tag(name:"affected", value:"'ghostscript' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);