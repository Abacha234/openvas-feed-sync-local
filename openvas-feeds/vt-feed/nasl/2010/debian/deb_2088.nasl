# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67843");
  script_cve_id("CVE-2010-2252");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2088)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2088");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2088");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'wget' package(s) announced via the DSA-2088 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wget, a command line tool for downloading files from the WWW, uses server-provided file names when creating local files. This may lead to code execution in some scenarios.

After this update, wget will ignore server-provided file names. You can restore the old behavior in cases where it is not desirable by invoking wget with the new --use-server-file-name option.

For the stable distribution (lenny), this problem has been fixed in version 1.11.4-2+lenny2.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your wget package.");

  script_tag(name:"affected", value:"'wget' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);