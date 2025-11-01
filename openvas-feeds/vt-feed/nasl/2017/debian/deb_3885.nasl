# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703885");
  script_cve_id("CVE-2017-9468", "CVE-2017-9469");
  script_tag(name:"creation_date", value:"2017-06-17 22:00:00 +0000 (Sat, 17 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-14 19:07:00 +0000 (Thu, 14 Mar 2019)");

  script_name("Debian: Security Advisory (DSA-3885)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3885");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3885");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'irssi' package(s) announced via the DSA-3885 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Irssi, a terminal based IRC client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2017-9468

Joseph Bisch discovered that Irssi does not properly handle DCC messages without source nick/host. A malicious IRC server can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

CVE-2017-9469

Joseph Bisch discovered that Irssi does not properly handle receiving incorrectly quoted DCC files. A remote attacker can take advantage of this flaw to cause Irssi to crash, resulting in a denial of service.

For the oldstable distribution (jessie), these problems have been fixed in version 0.8.17-1+deb8u4.

For the stable distribution (stretch), these problems have been fixed in version 1.0.2-1+deb9u1.

For the unstable distribution (sid), these problems have been fixed in version 1.0.3-1.

We recommend that you upgrade your irssi packages.");

  script_tag(name:"affected", value:"'irssi' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);