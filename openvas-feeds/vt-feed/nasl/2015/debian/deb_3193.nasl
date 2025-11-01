# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703193");
  script_cve_id("CVE-2015-0261", "CVE-2015-2153", "CVE-2015-2154", "CVE-2015-2155");
  script_tag(name:"creation_date", value:"2015-03-16 23:00:00 +0000 (Mon, 16 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3193)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3193");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3193");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tcpdump' package(s) announced via the DSA-3193 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in tcpdump, a command-line network traffic analyzer. These vulnerabilities might result in denial of service (application crash) or, potentially, execution of arbitrary code.

For the stable distribution (wheezy), these problems have been fixed in version 4.3.0-1+deb7u2.

For the upcoming stable distribution (jessie), these problems have been fixed in version 4.6.2-4.

For the unstable distribution (sid), these problems have been fixed in version 4.6.2-4.

We recommend that you upgrade your tcpdump packages.");

  script_tag(name:"affected", value:"'tcpdump' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);