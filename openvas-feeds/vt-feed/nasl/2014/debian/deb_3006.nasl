# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703006");
  script_cve_id("CVE-2013-1432", "CVE-2013-1442", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-2211", "CVE-2013-4329", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4494", "CVE-2013-4553", "CVE-2014-1950", "CVE-2014-2599", "CVE-2014-3124", "CVE-2014-4021");
  script_tag(name:"creation_date", value:"2014-08-17 22:00:00 +0000 (Sun, 17 Aug 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.4");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3006)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3006");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3006");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DSA-3006 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been discovered in the Xen virtualisation solution which may result in information leaks or denial of service.

For the stable distribution (wheezy), these problems have been fixed in version 4.1.4-3+deb7u2.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your xen packages.");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);