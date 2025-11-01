# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.68457");
  script_cve_id("CVE-2010-3170", "CVE-2010-3173");
  script_tag(name:"creation_date", value:"2010-11-17 02:33:48 +0000 (Wed, 17 Nov 2010)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2123");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2123");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'nss' package(s) announced via the DSA-2123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in Mozilla's Network Security Services (NSS) library. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-3170

NSS recognizes a wildcard IP address in the subject's Common Name field of an X.509 certificate, which might allow man-in-the-middle attackers to spoof arbitrary SSL servers via a crafted certificate issued by a legitimate Certification Authority.

CVE-2010-3173

NSS does not properly set the minimum key length for Diffie-Hellman Ephemeral (DHE) mode, which makes it easier for remote attackers to defeat cryptographic protection mechanisms via a brute-force attack.

For the stable distribution (lenny), these problems have been fixed in version 3.12.3.1-0lenny2.

For the unstable distribution (sid) and the upcoming stable distribution (squeeze), these problems have been fixed in version 3.12.8-1.

We recommend that you upgrade your NSS packages.");

  script_tag(name:"affected", value:"'nss' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);