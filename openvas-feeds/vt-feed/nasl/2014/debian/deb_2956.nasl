# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702956");
  script_cve_id("CVE-2013-7106", "CVE-2013-7107", "CVE-2013-7108", "CVE-2014-1878", "CVE-2014-2386");
  script_tag(name:"creation_date", value:"2014-06-10 22:00:00 +0000 (Tue, 10 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2956)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2956");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2956");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icinga' package(s) announced via the DSA-2956 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Icinga host and network monitoring system (buffer overflows, cross-site request forgery, off-by ones) which could result in the execution of arbitrary code, denial of service or session hijacking.

For the stable distribution (wheezy), these problems have been fixed in version 1.7.1-7.

For the testing distribution (jessie), these problems have been fixed in version 1.11.0-1.

For the unstable distribution (sid), these problems have been fixed in version 1.11.0-1.

We recommend that you upgrade your icinga packages.");

  script_tag(name:"affected", value:"'icinga' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);