# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60799");
  script_cve_id("CVE-2008-1558");
  script_tag(name:"creation_date", value:"2008-04-21 18:40:14 +0000 (Mon, 21 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1552)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1552");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1552");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mplayer' package(s) announced via the DSA-1552 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the MPlayer movie player performs insufficient input sanitising on SDP session data, leading to potential execution of arbitrary code through a malformed multimedia stream.

For the stable distribution (etch), this problem has been fixed in version 1.0~rc1-12etch3.

For the unstable distribution (sid), this problem has been fixed in version 1.0~rc2-10.

We recommend that you upgrade your mplayer package.");

  script_tag(name:"affected", value:"'mplayer' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);