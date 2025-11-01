# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63734");
  script_cve_id("CVE-2009-1171");
  script_tag(name:"creation_date", value:"2009-04-06 18:58:11 +0000 (Mon, 06 Apr 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1761)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1761");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1761");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-1761 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Christian J. Eibl discovered that the TeX filter of Moodle, a web-based course management system, doesn't check user input for certain TeX commands which allows an attacker to include and display the content of arbitrary system files.

Note that this doesn't affect installations that only use the mimetex environment.

For the oldstable distribution (etch), this problem has been fixed in version 1.6.3-2+etch3.

For the stable distribution (lenny), this problem has been fixed in version 1.8.2.dfsg-3+lenny2.

For the testing distribution (squeeze), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in version 1.8.2.dfsg-5.

We recommend that you upgrade your moodle packages.");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);