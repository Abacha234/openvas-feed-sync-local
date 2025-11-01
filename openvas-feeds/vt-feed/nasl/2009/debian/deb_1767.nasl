# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63794");
  script_cve_id("CVE-2009-0115");
  script_tag(name:"creation_date", value:"2009-04-15 20:11:00 +0000 (Wed, 15 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1767)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1767");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1767");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'multipath-tools' package(s) announced via the DSA-1767 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that multipathd of multipath-tools, a tool-chain to manage disk multipath device maps, uses insecure permissions on its unix domain control socket which enables local attackers to issue commands to multipathd prevent access to storage devices or corrupt file system data.

For the oldstable distribution (etch), this problem has been fixed in version 0.4.7-1.1etch2.

For the stable distribution (lenny), this problem has been fixed in version 0.4.8-14+lenny1.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 0.4.8-15.

We recommend that you upgrade your multipath-tools packages.");

  script_tag(name:"affected", value:"'multipath-tools' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);