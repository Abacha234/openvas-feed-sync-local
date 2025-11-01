# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70566");
  script_cve_id("CVE-2011-3872");
  script_tag(name:"creation_date", value:"2012-02-11 07:31:41 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2352)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2352");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2352");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'puppet' package(s) announced via the DSA-2352 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Puppet, a centralized configuration management solution, misgenerated certificates if the certdnsnames option was used. This could lead to man in the middle attacks. More details are available on the Puppet web site.

For the oldstable distribution (lenny), this problem has been fixed in version 0.24.5-3+lenny2.

For the stable distribution (squeeze), this problem has been fixed in version 2.6.2-5+squeeze3.

For the unstable distribution (sid), this problem has been fixed in version 2.7.6-1.

We recommend that you upgrade your puppet packages.");

  script_tag(name:"affected", value:"'puppet' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);