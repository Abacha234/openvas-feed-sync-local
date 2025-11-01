# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702621");
  script_cve_id("CVE-2013-0166", "CVE-2013-0169");
  script_tag(name:"creation_date", value:"2013-02-12 23:00:00 +0000 (Tue, 12 Feb 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Debian: Security Advisory (DSA-2621)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2621");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2621");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-2621 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been found in OpenSSL. The Common Vulnerabilities and Exposures project identifies the following issues:

CVE-2013-0166

OpenSSL does not properly perform signature verification for OCSP responses, which allows remote attackers to cause a denial of service via an invalid key.

CVE-2013-0169

A timing side channel attack has been found in CBC padding allowing an attacker to recover pieces of plaintext via statistical analysis of crafted packages, known as the Lucky Thirteen issue.

For the stable distribution (squeeze), these problems have been fixed in version 0.9.8o-4squeeze14.

For the testing distribution (wheezy), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 1.0.1e-1.

We recommend that you upgrade your openssl packages.");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);