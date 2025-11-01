# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840411");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-3555", "CVE-2010-0082", "CVE-2010-0084", "CVE-2010-0085", "CVE-2010-0088", "CVE-2010-0091", "CVE-2010-0092", "CVE-2010-0093", "CVE-2010-0094", "CVE-2010-0095", "CVE-2010-0837", "CVE-2010-0838", "CVE-2010-0840", "CVE-2010-0845", "CVE-2010-0847", "CVE-2010-0848");
  script_tag(name:"creation_date", value:"2010-04-09 09:11:25 +0000 (Fri, 09 Apr 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-923-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-923-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-923-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openjdk-6' package(s) announced via the USN-923-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Marsh Ray and Steve Dispensa discovered a flaw in the TLS and SSLv3
protocols. If an attacker could perform a machine-in-the-middle attack at the
start of a TLS connection, the attacker could inject arbitrary content
at the beginning of the user's session. (CVE-2009-3555)

It was discovered that Loader-constraint table, Policy/PolicyFile,
Inflater/Deflater, drag/drop access, and deserialization did not correctly
handle certain sensitive objects. If a user were tricked into running a
specially crafted applet, private information could be leaked to a remote
attacker, leading to a loss of privacy. (CVE-2010-0082, CVE-2010-0084,
CVE-2010-0085, CVE-2010-0088, CVE-2010-0091, CVE-2010-0094)

It was discovered that AtomicReferenceArray, System.arraycopy,
InetAddress, and HashAttributeSet did not correctly handle certain
situations. If a remote attacker could trigger specific error conditions,
a Java application could crash, leading to a denial of service.
(CVE-2010-0092, CVE-2010-0093, CVE-2010-0095, CVE-2010-0845)

It was discovered that Pack200, CMM readMabCurveData, ImagingLib, and
the AWT library did not correctly check buffer lengths. If a user or
automated system were tricked into handling specially crafted JAR files or
images, a remote attacker could crash the Java application or possibly
gain user privileges (CVE-2010-0837, CVE-2010-0838, CVE-2010-0847,
CVE-2010-0848).

It was discovered that applets did not correctly handle certain trust
chains. If a user were tricked into running a specially crafted applet,
a remote attacker could possibly run untrusted code with user privileges.
(CVE-2010-0840)");

  script_tag(name:"affected", value:"'openjdk-6' package(s) on Ubuntu 8.04, Ubuntu 8.10, Ubuntu 9.04, Ubuntu 9.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
