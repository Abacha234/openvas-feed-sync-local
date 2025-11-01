# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893345");
  script_cve_id("CVE-2022-31631", "CVE-2023-0567", "CVE-2023-0568", "CVE-2023-0662");
  script_tag(name:"creation_date", value:"2023-02-27 02:00:07 +0000 (Mon, 27 Feb 2023)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 18:02:00 +0000 (Fri, 03 Mar 2023)");

  script_name("Debian: Security Advisory (DLA-3345)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-3345");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3345");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.3");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.3' package(s) announced via the DLA-3345 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in PHP, a widely-used open source general purpose scripting language, which could result in denial of service or incorrect validation of BCrypt hashes.

CVE-2022-31631

Due to an uncaught integer overflow, PDO::quote() of PDO_SQLite may return an improperly quoted string. The exact details likely depend on the implementation of sqlite3_snprintf(), but with some versions it is possible to force the function to return a single apostrophe, if the function is called on user supplied input without any length restrictions in place.

CVE-2023-0567

Tim Dusterhus discovered that malformed BCrypt hashes that include a $ character within their salt part trigger a buffer overread and may erroneously validate any password as valid. (Password_verify() always returns true with such inputs.)

CVE-2023-0568

1-byte array overrun when appending slash to paths during path resolution.

CVE-2023-0662

Jakob Ackermann discovered a Denial of Service vulnerability when parsing multipart request body: the request body parsing in PHP allows any unauthenticated attacker to consume a large amount of CPU time and trigger excessive logging.

For Debian 10 buster, these problems have been fixed in version 7.3.31-1~deb10u3.

We recommend that you upgrade your php7.3 packages.

For the detailed security status of php7.3 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'php7.3' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);