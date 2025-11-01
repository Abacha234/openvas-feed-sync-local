# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703025");
  script_cve_id("CVE-2014-0487", "CVE-2014-0488", "CVE-2014-0489", "CVE-2014-0490");
  script_tag(name:"creation_date", value:"2014-09-15 22:00:00 +0000 (Mon, 15 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3025)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3025");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3025");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'apt' package(s) announced via the DSA-3025 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that APT, the high level package manager, does not properly invalidate unauthenticated data ( CVE-2014-0488), performs incorrect verification of 304 replies ( CVE-2014-0487), does not perform the checksum check when the Acquire::GzipIndexes option is used ( CVE-2014-0489) and does not properly perform validation for binary packages downloaded by the apt-get download command ( CVE-2014-0490).

For the stable distribution (wheezy), these problems have been fixed in version 0.9.7.9+deb7u3.

For the unstable distribution (sid), these problems have been fixed in version 1.0.9.

We recommend that you upgrade your apt packages.");

  script_tag(name:"affected", value:"'apt' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);