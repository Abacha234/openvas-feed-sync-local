# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67637");
  script_cve_id("CVE-2010-2451", "CVE-2010-2452");
  script_tag(name:"creation_date", value:"2010-07-06 00:35:12 +0000 (Tue, 06 Jul 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2065)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2065");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2065");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kvirc' package(s) announced via the DSA-2065 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been discovered in the DCC protocol support code of kvirc, a KDE-based next generation IRC client, which allow the overwriting of local files through directory traversal and the execution of arbitrary code through a format string attack.

For the stable distribution (lenny), these problems have been fixed in version 3.4.0-5.

For the unstable distribution (sid), these problems have been fixed in version 4.0.0~svn4340+rc3-1.

We recommend that you upgrade your kvirc packages.");

  script_tag(name:"affected", value:"'kvirc' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);