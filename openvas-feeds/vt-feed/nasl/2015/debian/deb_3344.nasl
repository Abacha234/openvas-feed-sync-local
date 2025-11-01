# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703344");
  script_cve_id("CVE-2015-4598", "CVE-2015-4643", "CVE-2015-4644", "CVE-2015-5589", "CVE-2015-5590", "CVE-2015-6831", "CVE-2015-6832", "CVE-2015-6833");
  script_tag(name:"creation_date", value:"2015-08-26 22:00:00 +0000 (Wed, 26 Aug 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-04 01:29:00 +0000 (Sat, 04 Nov 2017)");

  script_name("Debian: Security Advisory (DSA-3344)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3344");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3344");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php5' package(s) announced via the DSA-3344 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the PHP language:

CVE-2015-4598

thoger at redhat dot com discovered that paths containing a NUL character were improperly handled, thus allowing an attacker to manipulate unexpected files on the server.

CVE-2015-4643

Max Spelsberg discovered an integer overflow flaw leading to a heap-based buffer overflow in PHP's FTP extension, when parsing listings in FTP server responses. This could lead to a crash or execution of arbitrary code.

CVE-2015-4644

A denial of service through a crash could be caused by a segfault in the php_pgsql_meta_data function.

CVE-2015-5589

kwrnel at hotmail dot com discovered that PHP could crash when processing an invalid phar file, thus leading to a denial of service.

CVE-2015-5590

jared at enhancesoft dot com discovered a buffer overflow in the phar_fix_filepath function, that could causes a crash or execution of arbitrary code.

Additionally, several other vulnerabilities were fixed:

sean dot heelan at gmail dot com discovered a problem in the unserialization of some items, that could lead to arbitrary code execution.

stewie at mail dot ru discovered that the phar extension improperly handled zip archives with relative paths, which would allow an attacker to overwrite files outside of the destination directory.

taoguangchen at icloud dot com discovered several use-after-free vulnerabilities that could lead to arbitrary code execution.

For the oldstable distribution (wheezy), these problems have been fixed in version 5.4.44-0+deb7u1.

For the stable distribution (jessie), these problems have been fixed in version 5.6.12+dfsg-0+deb8u1.

For the unstable distribution (sid), these problems have been fixed in version 5.6.12+dfsg-1.

We recommend that you upgrade your php5 packages.");

  script_tag(name:"affected", value:"'php5' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);