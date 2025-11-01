# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61712");
  script_cve_id("CVE-2008-3658", "CVE-2008-3659", "CVE-2008-3660");
  script_tag(name:"creation_date", value:"2008-10-08 22:42:36 +0000 (Wed, 08 Oct 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1647)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1647");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1647");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-1647 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in PHP, a server-side, HTML-embedded scripting language. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-3658

Buffer overflow in the imageloadfont function allows a denial of service or code execution through a crafted font file.

CVE-2008-3659

Buffer overflow in the memnstr function allows a denial of service or code execution via a crafted delimiter parameter to the explode function.

CVE-2008-3660

Denial of service is possible in the FastCGI module by a remote attacker by making a request with multiple dots before the extension.

For the stable distribution (etch), these problems have been fixed in version 5.2.0-8+etch13.

For the testing (lenny) and unstable distribution (sid), these problems have been fixed in version 5.2.6-4.

We recommend that you upgrade your php5 package.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);