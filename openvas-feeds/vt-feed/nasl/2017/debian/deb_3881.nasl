# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703881");
  script_cve_id("CVE-2017-5470", "CVE-2017-5472", "CVE-2017-7749", "CVE-2017-7750", "CVE-2017-7751", "CVE-2017-7752", "CVE-2017-7754", "CVE-2017-7756", "CVE-2017-7757", "CVE-2017-7758", "CVE-2017-7764", "CVE-2017-7771", "CVE-2017-7772", "CVE-2017-7773", "CVE-2017-7774", "CVE-2017-7776", "CVE-2017-7777", "CVE-2017-7778");
  script_tag(name:"creation_date", value:"2017-06-13 22:00:00 +0000 (Tue, 13 Jun 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-13 17:14:00 +0000 (Mon, 13 Aug 2018)");

  script_name("Debian: Security Advisory (DSA-3881)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3881");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3881");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DSA-3881 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been found in the Mozilla Firefox web browser: Multiple memory safety errors, use-after-frees, buffer overflows and other implementation errors may lead to the execution of arbitrary code, denial of service or domain spoofing.

Debian follows the extended support releases (ESR) of Firefox. Support for the 45.x series has ended, so starting with this update we're now following the 52.x releases.

For the stable distribution (jessie), these problems have been fixed in version 52.2.0esr-1~deb8u1.

For the upcoming stable distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 52.2.0esr-1.

We recommend that you upgrade your firefox-esr packages.");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 8, Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);