# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704009");
  script_cve_id("CVE-2017-15924");
  script_tag(name:"creation_date", value:"2017-10-28 22:00:00 +0000 (Sat, 28 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-4009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4009");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4009");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'shadowsocks-libev' package(s) announced via the DSA-4009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Niklas Abel discovered that insufficient input sanitising in the ss-manager component of shadowsocks-libev, a lightweight socks5 proxy, could result in arbitrary shell command execution.

For the stable distribution (stretch), this problem has been fixed in version 2.6.3+ds-3+deb9u1.

We recommend that you upgrade your shadowsocks-libev packages.");

  script_tag(name:"affected", value:"'shadowsocks-libev' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);