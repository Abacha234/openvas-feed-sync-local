# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71486");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725");
  script_tag(name:"creation_date", value:"2012-08-10 07:08:11 +0000 (Fri, 10 Aug 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2507)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2507");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2507");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjdk-6' package(s) announced via the DSA-2507 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJDK, an implementation of the Oracle Java platform.

CVE-2012-1711

CVE-2012-1719

Multiple errors in the CORBA implementation could lead to breakouts of the Java sandbox.

CVE-2012-1713

Missing input sanitising in the font manager could lead to the execution of arbitrary code.

CVE-2012-1716

The SynthLookAndFeel Swing class could be abused to break out of the Java sandbox.

CVE-2012-1717

Several temporary files were created insecurely, resulting in local information disclosure.

CVE-2012-1718

Certificate revocation lists were incorrectly implemented.

CVE-2012-1723

CVE-2012-1725

Validation errors in the bytecode verifier of the Hotspot VM could lead to breakouts of the Java sandbox.

CVE-2012-1724

Missing input sanitising in the XML parser could lead to denial of service through an infinite loop.

For the stable distribution (squeeze), this problem has been fixed in version 6b18-1.8.13-0+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 6b24-1.11.3-1.

We recommend that you upgrade your openjdk-6 packages.");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);