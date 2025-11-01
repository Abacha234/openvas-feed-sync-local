# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63099");
  script_cve_id("CVE-2008-3443");
  script_tag(name:"creation_date", value:"2009-01-07 22:16:01 +0000 (Wed, 07 Jan 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-1695)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1695");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1695");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.8, ruby1.9' package(s) announced via the DSA-1695 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The regular expression engine of Ruby, a scripting language, contains a memory leak which can be triggered remotely under certain circumstances, leading to a denial of service condition (CVE-2008-3443).

In addition, this security update addresses a regression in the REXML XML parser of the ruby1.8 package, the regression was introduced in DSA-1651-1.

For the stable distribution (etch), this problem has been fixed in version 1.8.5-4etch4 of the ruby1.8 package, and version 1.9.0+20060609-1etch4 of the ruby1.9 package.

For the unstable distribution (sid), this problem has been fixed in version 1.8.7.72-1 of the ruby1.8 package. The ruby1.9 package will be fixed soon.

We recommend that you upgrade your Ruby packages.");

  script_tag(name:"affected", value:"'ruby1.8, ruby1.9' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);