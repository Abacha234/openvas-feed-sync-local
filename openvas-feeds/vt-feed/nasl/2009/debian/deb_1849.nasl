# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.64561");
  script_cve_id("CVE-2009-0217");
  script_tag(name:"creation_date", value:"2009-08-17 14:54:45 +0000 (Mon, 17 Aug 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1849)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1849");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1849");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xml-security-c' package(s) announced via the DSA-1849 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the W3C XML Signature recommendation contains a protocol-level vulnerability related to HMAC output truncation. This update implements the proposed workaround in the C++ version of the Apache implementation of this standard, xml-security-c, by preventing truncation to output strings shorter than 80 bits or half of the original HMAC output, whichever is greater.

For the old stable distribution (etch), this problem has been fixed in version 1.2.1-3+etch1.

For the stable distribution (lenny), this problem has been fixed in version 1.4.0-3+lenny2.

For the unstable distribution (sid), this problem has been fixed in version 1.4.0-4.

We recommend that you upgrade your xml-security-c packages.");

  script_tag(name:"affected", value:"'xml-security-c' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);