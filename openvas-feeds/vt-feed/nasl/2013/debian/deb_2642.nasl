# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702642");
  script_cve_id("CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776", "CVE-2013-2777");
  script_tag(name:"creation_date", value:"2013-03-08 23:00:00 +0000 (Fri, 08 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2642)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2642");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2642");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sudo' package(s) announced via the DSA-2642 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in sudo, a program designed to allow a sysadmin to give limited root privileges to users. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2013-1775

Marco Schoepl discovered an authentication bypass when the clock is set to the UNIX epoch [00:00:00 UTC on 1 January 1970].

CVE-2013-1776

Ryan Castellucci and James Ogden discovered aspects of an issue that would allow session id hijacking from another authorized tty.

For the stable distribution (squeeze), these problems have been fixed in version 1.7.4p4-2.squeeze.4.

For the testing (wheezy) and unstable (sid) distributions, these problems have been fixed in version 1.8.5p2-1+nmu1.

We recommend that you upgrade your sudo packages.");

  script_tag(name:"affected", value:"'sudo' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);