# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703984");
  script_cve_id("CVE-2017-14867");
  script_tag(name:"creation_date", value:"2017-09-25 22:00:00 +0000 (Mon, 25 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-26 14:55:00 +0000 (Tue, 26 Jan 2021)");

  script_name("Debian: Security Advisory (DSA-3984)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3984");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3984");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git' package(s) announced via the DSA-3984 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"joernchen discovered that the git-cvsserver subcommand of Git, a distributed version control system, suffers from a shell command injection vulnerability due to unsafe use of the Perl backtick operator. The git-cvsserver subcommand is reachable from the git-shell subcommand even if CVS support has not been configured (however, the git-cvs package needs to be installed).

In addition to fixing the actual bug, this update removes the cvsserver subcommand from git-shell by default. Refer to the updated documentation for instructions how to re-enable in case this CVS functionality is still needed.

For the oldstable distribution (jessie), this problem has been fixed in version 1:2.1.4-2.1+deb8u5.

For the stable distribution (stretch), this problem has been fixed in version 1:2.11.0-3+deb9u2.

For the unstable distribution (sid), this problem has been fixed in version 1:2.14.2-1.

We recommend that you upgrade your git packages.");

  script_tag(name:"affected", value:"'git' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);