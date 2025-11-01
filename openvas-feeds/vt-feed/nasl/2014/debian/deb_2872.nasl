# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702872");
  script_cve_id("CVE-2014-0004");
  script_tag(name:"creation_date", value:"2014-03-09 23:00:00 +0000 (Sun, 09 Mar 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2872)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2872");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2872");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'udisks' package(s) announced via the DSA-2872 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Florian Weimer discovered a buffer overflow in udisks's mount path parsing code which may result in privilege escalation.

For the oldstable distribution (squeeze), this problem has been fixed in version 1.0.1+git20100614-3squeeze1.

For the stable distribution (wheezy), this problem has been fixed in version 1.0.4-7wheezy1.

For the unstable distribution (sid), this problem has been fixed in version 1.0.5-1.

We recommend that you upgrade your udisks packages.");

  script_tag(name:"affected", value:"'udisks' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);