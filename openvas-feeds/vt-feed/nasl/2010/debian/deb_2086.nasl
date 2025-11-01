# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.67842");
  script_cve_id("CVE-2009-0758", "CVE-2010-2244");
  script_tag(name:"creation_date", value:"2010-08-21 06:54:16 +0000 (Sat, 21 Aug 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Debian: Security Advisory (DSA-2086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2086");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2086");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'avahi' package(s) announced via the DSA-2086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Avahi mDNS/DNS-SD daemon. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0758

Rob Leslie discovered a denial of service vulnerability in the code used to reflect unicast mDNS traffic.

CVE-2010-2244

Ludwig Nussel discovered a denial of service vulnerability in the processing of malformed DNS packets.

For the stable distribution (lenny), these problems have been fixed in version 0.6.23-3lenny2.

For the unstable distribution (sid), these problems have been fixed in version 0.6.26-1.

We recommend that you upgrade your Avahi packages.");

  script_tag(name:"affected", value:"'avahi' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);