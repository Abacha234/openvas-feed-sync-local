# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57208");
  script_cve_id("CVE-2006-3694");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1139)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1139");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/dsa-1139");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby1.6' package(s) announced via the DSA-1139 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the interpreter for the Ruby language does not properly maintain 'safe levels' for aliasing, directory accesses and regular expressions, which might lead to a bypass of security restrictions.

For the stable distribution (sarge) this problem has been fixed in version 1.6.8-12sarge2.

The unstable distribution (sid) does no longer contain ruby1.6 packages.

We recommend that you upgrade your Ruby packages.");

  script_tag(name:"affected", value:"'ruby1.6' package(s) on Debian 3.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);