# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703964");
  script_cve_id("CVE-2017-14099", "CVE-2017-14100");
  script_tag(name:"creation_date", value:"2017-09-03 22:00:00 +0000 (Sun, 03 Sep 2017)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Debian: Security Advisory (DSA-3964)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3964");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3964");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-005.html");
  script_xref(name:"URL", value:"http://downloads.asterisk.org/pub/security/AST-2017-006.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-3964 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Asterisk, an open source PBX and telephony toolkit, which may result in disclosure of RTP connections or the execution of arbitrary shell commands.

For additional information please refer to the upstream advisories: [link moved to references] [link moved to references]

For the oldstable distribution (jessie), these problems have been fixed in version 1:11.13.1~dfsg-2+deb8u3.

For the stable distribution (stretch), these problems have been fixed in version 1:13.14.1~dfsg-2+deb9u1.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
