# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702622");
  script_cve_id("CVE-2013-0169", "CVE-2013-1621");
  script_tag(name:"creation_date", value:"2013-02-12 23:00:00 +0000 (Tue, 12 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2622)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2622");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2622");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'polarssl' package(s) announced via the DSA-2622 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in PolarSSL. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-0169

A timing side channel attack has been found in CBC padding allowing an attacker to recover pieces of plaintext via statistical analysis of crafted packages, known as the Lucky Thirteen issue.

CVE-2013-1621

An array index error might allow remote attackers to cause a denial of service via vectors involving a crafted padding-length value during validation of CBC padding in a TLS session.

CVE-2013-1622

Malformed CBC data in a TLS session could allow remote attackers to conduct distinguishing attacks via statistical analysis of timing side-channel data for crafted packets.

For the stable distribution (squeeze), these problems have been fixed in version 0.12.1-1squeeze1.

For the testing distribution (wheezy), and the unstable distribution (sid), these problems have been fixed in version 1.1.4-2.

We recommend that you upgrade your polarssl packages.");

  script_tag(name:"affected", value:"'polarssl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);