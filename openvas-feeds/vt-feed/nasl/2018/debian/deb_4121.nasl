# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704121");
  script_tag(name:"creation_date", value:"2018-02-21 23:00:00 +0000 (Wed, 21 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-4121)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4121");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4121");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gcc-6' package(s) announced via the DSA-4121 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update doesn't fix a vulnerability in GCC itself, but instead provides support for building retpoline-enabled Linux kernel updates.

For the stable distribution (stretch), this problem has been fixed in version 6.3.0-18+deb9u1.

We recommend that you upgrade your gcc-6 packages.");

  script_tag(name:"affected", value:"'gcc-6' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);