# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61640");
  script_cve_id("CVE-2008-3195");
  script_tag(name:"creation_date", value:"2008-09-24 15:42:31 +0000 (Wed, 24 Sep 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1639)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1639");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1639");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'twiki' package(s) announced via the DSA-1639 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that twiki, a web based collaboration platform, didn't properly sanitize the image parameter in its configuration script. This could allow remote users to execute arbitrary commands upon the system, or read any files which were readable by the webserver user.

For the stable distribution (etch), this problem has been fixed in version 1:4.0.5-9.1etch1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your twiki package.");

  script_tag(name:"affected", value:"'twiki' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);