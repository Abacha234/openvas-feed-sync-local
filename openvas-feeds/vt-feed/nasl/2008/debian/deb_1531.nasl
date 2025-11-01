# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60656");
  script_cve_id("CVE-2008-1569", "CVE-2008-1570");
  script_tag(name:"creation_date", value:"2008-04-07 18:38:54 +0000 (Mon, 07 Apr 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1531)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1531");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1531");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'policyd-weight' package(s) announced via the DSA-1531 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chris Howells discovered that policyd-weight, a policy daemon for the Postfix mail transport agent, created its socket in an insecure way, which may be exploited to overwrite or remove arbitrary files from the local system.

For the stable distribution (etch), this problem has been fixed in version 0.1.14-beta-6etch2.

The old stable distribution (sarge) does not contain a policyd-weight package.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your policyd-weight package.");

  script_tag(name:"affected", value:"'policyd-weight' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);