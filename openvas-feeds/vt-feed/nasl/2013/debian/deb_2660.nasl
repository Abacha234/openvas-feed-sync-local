# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702660");
  script_cve_id("CVE-2013-1944");
  script_tag(name:"creation_date", value:"2013-04-19 22:00:00 +0000 (Fri, 19 Apr 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2660)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2660");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2660");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'curl' package(s) announced via the DSA-2660 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Yamada Yasuharu discovered that cURL, an URL transfer library, is vulnerable to expose potentially sensitive information when doing requests across domains with matching tails. Due to a bug in the tailmatch function when matching domain names, it was possible that cookies set for a domain ample.com could accidentally also be sent by libcurl when communicating with example.com.

Both curl the command line tool and applications using the libcurl library are vulnerable.

For the stable distribution (squeeze), this problem has been fixed in version 7.21.0-2.1+squeeze3.

For the testing distribution (wheezy), this problem has been fixed in version 7.26.0-1+wheezy2.

For the unstable distribution (sid), this problem has been fixed in version 7.29.0-2.1.

We recommend that you upgrade your curl packages.");

  script_tag(name:"affected", value:"'curl' package(s) on Debian 6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);