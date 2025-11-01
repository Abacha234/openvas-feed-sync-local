# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60863");
  script_cve_id("CVE-2008-1380");
  script_tag(name:"creation_date", value:"2008-04-30 17:28:13 +0000 (Wed, 30 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1558)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1558");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1558");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xulrunner' package(s) announced via the DSA-1558 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that crashes in the Javascript engine of xulrunner, the Gecko engine library, could potentially lead to the execution of arbitrary code.

For the stable distribution (etch), this problem has been fixed in version 1.8.0.15~pre080323b-0etch2.

For the unstable distribution (sid), this problem has been fixed in version 1.8.1.14-1.

We recommend that you upgrade your xulrunner packages.");

  script_tag(name:"affected", value:"'xulrunner' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);