# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71262");
  script_cve_id("CVE-2012-1183", "CVE-2012-2414", "CVE-2012-2415");
  script_tag(name:"creation_date", value:"2012-04-30 11:58:08 +0000 (Mon, 30 Apr 2012)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2460)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2460");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/dsa-2460");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-2460 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the Asterisk PBX and telephony toolkit:

CVE-2012-1183

Russell Bryant discovered a buffer overflow in the Milliwatt application.

CVE-2012-2414

David Woolley discovered a privilege escalation in the Asterisk manager interface.

CVE-2012-2415

Russell Bryant discovered a buffer overflow in the Skinny driver.

For the stable distribution (squeeze), this problem has been fixed in version 1:1.6.2.9-2+squeeze5.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);