# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702961");
  script_cve_id("CVE-2014-4049");
  script_tag(name:"creation_date", value:"2014-06-15 22:00:00 +0000 (Sun, 15 Jun 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2961)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2961");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2961");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-2961 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that PHP, a general-purpose scripting language commonly used for web application development, is vulnerable to a heap-based buffer overflow in the DNS TXT record parsing. A malicious server or man-in-the-middle attacker could possibly use this flaw to execute arbitrary code as the PHP interpreter if a PHP application uses dns_get_record() to perform a DNS query.

For the stable distribution (wheezy), this problem has been fixed in version 5.4.4-14+deb7u11.

For the testing distribution (jessie), this problem has been fixed in version 5.6.0~beta4+dfsg-3.

For the unstable distribution (sid), this problem has been fixed in version 5.6.0~beta4+dfsg-3.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);