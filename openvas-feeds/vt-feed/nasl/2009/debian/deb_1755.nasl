# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63685");
  script_cve_id("CVE-2009-0784");
  script_tag(name:"creation_date", value:"2009-03-31 17:20:21 +0000 (Tue, 31 Mar 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1755)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1755");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1755");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'systemtap' package(s) announced via the DSA-1755 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Erik Sjoelund discovered that a race condition in the stap tool shipped by Systemtap, an instrumentation system for Linux 2.6, allows local privilege escalation for members of the stapusr group.

The old stable distribution (etch) isn't affected.

For the stable distribution (lenny), this problem has been fixed in version 0.0.20080705-1+lenny1.

For the unstable distribution (sid), this problem has been fixed in version 0.0.20090314-2.

We recommend that you upgrade your systemtap package.");

  script_tag(name:"affected", value:"'systemtap' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);