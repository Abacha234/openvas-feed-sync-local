# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.69983");
  script_cve_id("CVE-2011-2516");
  script_tag(name:"creation_date", value:"2011-08-03 02:36:20 +0000 (Wed, 03 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2277");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/dsa-2277");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xml-security-c' package(s) announced via the DSA-2277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It has been discovered that xml-security-c, an implementation of the XML Digital Signature and Encryption specifications, is not properly handling RSA keys of sizes on the order of 8192 or more bits. This allows an attacker to crash applications using this functionality or potentially execute arbitrary code by tricking an application into verifying a signature created with a sufficiently long RSA key.

For the oldstable distribution (lenny), this problem has been fixed in version 1.4.0-3+lenny3.

For the stable distribution (squeeze), this problem has been fixed in version 1.5.1-3+squeeze1.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.6.1-1.

We recommend that you upgrade your xml-security-c packages.");

  script_tag(name:"affected", value:"'xml-security-c' package(s) on Debian 5, Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);