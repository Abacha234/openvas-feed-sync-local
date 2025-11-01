# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703521");
  script_cve_id("CVE-2016-2315", "CVE-2016-2324");
  script_tag(name:"creation_date", value:"2016-03-18 23:00:00 +0000 (Fri, 18 Mar 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Debian: Security Advisory (DSA-3521)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3521");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3521");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'git' package(s) announced via the DSA-3521 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lael Cellier discovered two buffer overflow vulnerabilities in git, a fast, scalable, distributed revision control system, which could be exploited for remote execution of arbitrary code.

For the oldstable distribution (wheezy), these problems have been fixed in version 1:1.7.10.4-1+wheezy3.

For the stable distribution (jessie), these problems have been fixed in version 1:2.1.4-2.1+deb8u2.

For the unstable distribution (sid), these problems have been fixed in version 1:2.8.0~rc3-1. CVE-2016-2315 was already fixed in version 1:2.7.0-1.

We recommend that you upgrade your git packages.");

  script_tag(name:"affected", value:"'git' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);