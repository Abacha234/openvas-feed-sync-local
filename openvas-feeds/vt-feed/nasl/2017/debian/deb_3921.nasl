# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703921");
  script_tag(name:"creation_date", value:"2017-07-27 22:00:00 +0000 (Thu, 27 Jul 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3921)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3921");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3921");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'enigmail' package(s) announced via the DSA-3921 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In DSA 3918 Thunderbird was upgraded to the latest ESR series. This update upgrades Enigmail, the OpenPGP extension for Thunderbird, to version 1.9.8.1 to restore full compatibility.

For the oldstable distribution (jessie), this problem has been fixed in version 2:1.9.8.1-1~deb8u1.

For the stable distribution (stretch), this problem has been fixed in version 2:1.9.8.1-1~deb9u1.

We recommend that you upgrade your enigmail packages.");

  script_tag(name:"affected", value:"'enigmail' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);