# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892938");
  script_cve_id("CVE-2022-21716");
  script_tag(name:"creation_date", value:"2022-03-09 02:00:04 +0000 (Wed, 09 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-10 17:45:00 +0000 (Thu, 10 Mar 2022)");

  script_name("Debian: Security Advisory (DLA-2938)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2938");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2938");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'twisted' package(s) announced via the DLA-2938 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an issue in the Twisted Python network framework where SSH client and server implementations could accept an infinite amount of data for the peer's SSH version identifier and that a buffer then uses all available memory.

CVE-2022-21716

CVE-2022-21716: Twisted is an event-based framework for internet applications, supporting Python 3.6+. Prior to 22.2.0, Twisted SSH client and server implement is able to accept an infinite amount of data for the peer's SSH version identifier. This ends up with a buffer using all the available memory. The attach is a simple as `nc -rv localhost 22 < /dev/zero`. A patch is available in version 22.2.0. There are currently no known workarounds.

For Debian 9 Stretch, this problem has been fixed in version 16.6.0-2+deb9u2.

We recommend that you upgrade your twisted packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'twisted' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
