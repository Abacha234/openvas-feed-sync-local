# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703037");
  script_cve_id("CVE-2014-1568");
  script_tag(name:"creation_date", value:"2014-10-01 11:30:18 +0000 (Wed, 01 Oct 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3037)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3037");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-3037");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-3037 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Antoine Delignat-Lavaud from Inria discovered an issue in the way NSS (the Mozilla Network Security Service library, embedded in Wheezy's Icedove), was parsing ASN.1 data used in signatures, making it vulnerable to a signature forgery attack.

An attacker could craft ASN.1 data to forge RSA certificates with a valid certification chain to a trusted CA.

For the stable distribution (wheezy), this problem has been fixed in version 24.8.1-1~deb7u1.

For the testing distribution (jessie) and unstable distribution (sid), Icedove uses the system NSS library, handled in DSA 3033-1.

We recommend that you upgrade your icedove packages.");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);