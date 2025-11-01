# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704240");
  script_cve_id("CVE-2018-10545", "CVE-2018-10546", "CVE-2018-10547", "CVE-2018-10548", "CVE-2018-10549", "CVE-2018-7584");
  script_tag(name:"creation_date", value:"2018-07-04 22:00:00 +0000 (Wed, 04 Jul 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-19 11:15:00 +0000 (Mon, 19 Aug 2019)");

  script_name("Debian: Security Advisory (DSA-4240)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4240");
  script_xref(name:"URL", value:"https://www.debian.org/security/2018/dsa-4240");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.0' package(s) announced via the DSA-4240 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in PHP, a widely-used open source general purpose scripting language:

CVE-2018-7584

Buffer underread in parsing HTTP responses

CVE-2018-10545

Dumpable FPM child processes allowed the bypass of opcache access controls

CVE-2018-10546

Denial of service via infinite loop in convert.iconv stream filter

CVE-2018-10547

The fix for CVE-2018-5712 (shipped in DSA 4080) was incomplete

CVE-2018-10548

Denial of service via malformed LDAP server responses

CVE-2018-10549

Out-of-bounds read when parsing malformed JPEG files

For the stable distribution (stretch), these problems have been fixed in version 7.0.30-0+deb9u1.

We recommend that you upgrade your php7.0 packages.

For the detailed security status of php7.0 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.0' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);