# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703191");
  script_cve_id("CVE-2015-0282", "CVE-2015-0294");
  script_tag(name:"creation_date", value:"2015-03-14 23:00:00 +0000 (Sat, 14 Mar 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-31 15:24:00 +0000 (Fri, 31 Jan 2020)");

  script_name("Debian: Security Advisory (DSA-3191)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3191");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3191");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnutls26' package(s) announced via the DSA-3191 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in GnuTLS, a library implementing the TLS and SSL protocols. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-0282

GnuTLS does not verify the RSA PKCS #1 signature algorithm to match the signature algorithm in the certificate, leading to a potential downgrade to a disallowed algorithm without detecting it.

CVE-2015-0294

It was reported that GnuTLS does not check whether the two signature algorithms match on certificate import.

For the stable distribution (wheezy), these problems have been fixed in version 2.12.20-8+deb7u3.

We recommend that you upgrade your gnutls26 packages.");

  script_tag(name:"affected", value:"'gnutls26' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);