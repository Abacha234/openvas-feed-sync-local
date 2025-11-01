# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703074");
  script_cve_id("CVE-2014-3710");
  script_tag(name:"creation_date", value:"2014-11-17 23:00:00 +0000 (Mon, 17 Nov 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-3074)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3074");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3074");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3074 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Francisco Alonso of Red Hat Product Security found an issue in the file utility, whose code is embedded in PHP, a general-purpose scripting language. When checking ELF files, note headers are incorrectly checked, thus potentially allowing attackers to cause a denial of service (out-of-bounds read and application crash) by supplying a specially crafted ELF file.

As announced in DSA-3064-1 it has been decided to follow the stable 5.4.x releases for the Wheezy php5 packages. Consequently the vulnerability is addressed by upgrading PHP to a new upstream version 5.4.35, which includes additional bug fixes, new features and possibly incompatible changes. Please refer to the upstream changelog for more information:


For the stable distribution (wheezy), this problem has been fixed in version 5.4.35-0+deb7u1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);