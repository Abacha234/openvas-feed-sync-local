# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704591");
  script_cve_id("CVE-2019-19906");
  script_tag(name:"creation_date", value:"2019-12-21 03:00:05 +0000 (Sat, 21 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Debian: Security Advisory (DSA-4591)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4591");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4591");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/cyrus-sasl2");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cyrus-sasl2' package(s) announced via the DSA-4591 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Stephan Zeisberg reported an out-of-bounds write vulnerability in the _sasl_add_string() function in cyrus-sasl2, a library implementing the Simple Authentication and Security Layer. A remote attacker can take advantage of this issue to cause denial-of-service conditions for applications using the library.

For the oldstable distribution (stretch), this problem has been fixed in version 2.1.27~101-g0780600+dfsg-3+deb9u1.

For the stable distribution (buster), this problem has been fixed in version 2.1.27+dfsg-1+deb10u1.

We recommend that you upgrade your cyrus-sasl2 packages.

For the detailed security status of cyrus-sasl2 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'cyrus-sasl2' package(s) on Debian 9, Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);