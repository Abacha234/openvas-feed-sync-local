# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703137");
  script_cve_id("CVE-2013-6892");
  script_tag(name:"creation_date", value:"2015-01-23 23:00:00 +0000 (Fri, 23 Jan 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-3137)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3137");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3137");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'websvn' package(s) announced via the DSA-3137 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"James Clawson discovered that websvn, a web viewer for Subversion repositories, would follow symlinks in a repository when presenting a file for download. An attacker with repository write access could thereby access any file on disk readable by the user the webserver runs as.

For the stable distribution (wheezy), this problem has been fixed in version 2.3.3-1.1+deb7u1.

For the unstable distribution (sid), this problem has been fixed in version 2.3.3-1.2.

We recommend that you upgrade your websvn packages.");

  script_tag(name:"affected", value:"'websvn' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);