# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702641");
  script_cve_id("CVE-2013-1667");
  script_tag(name:"creation_date", value:"2013-03-19 23:00:00 +0000 (Tue, 19 Mar 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2641)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2641");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2641");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'perl' package(s) announced via the DSA-2641 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yves Orton discovered a flaw in the rehashing code of Perl. This flaw could be exploited to carry out a denial of service attack against code that uses arbitrary user input as hash keys. Specifically an attacker could create a set of keys of a hash causing a denial of service via memory exhaustion.

For the stable distribution (squeeze), this problem has been fixed in version 5.10.1-17squeeze6 of perl and version 2.0.4-7+squeeze1 of libapache2-mod-perl2.

For the testing distribution (wheezy), and the unstable distribution (sid), this problem has been fixed in version 5.14.2-19 of perl and version 2.0.7-3 of libapache2-mod-perl2.

We recommend that you upgrade your perl and libapache2-mod-perl2 packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);