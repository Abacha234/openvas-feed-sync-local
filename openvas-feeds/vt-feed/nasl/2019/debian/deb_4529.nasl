# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704529");
  script_cve_id("CVE-2019-11034", "CVE-2019-11035", "CVE-2019-11036", "CVE-2019-11038", "CVE-2019-11039", "CVE-2019-11040", "CVE-2019-11041", "CVE-2019-11042", "CVE-2019-13224");
  script_tag(name:"creation_date", value:"2019-09-24 02:00:11 +0000 (Tue, 24 Sep 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-20 16:33:00 +0000 (Wed, 20 Jul 2022)");

  script_name("Debian: Security Advisory (DSA-4529)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4529");
  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4529");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/php7.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'php7.0' package(s) announced via the DSA-4529 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were found in PHP, a widely-used open source general purpose scripting language: Missing sanitising in the EXIF extension and the iconv_mime_decode_headers() function could result in information disclosure or denial of service.

For the oldstable distribution (stretch), these problems have been fixed in version 7.0.33-0+deb9u5.

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