# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843323");
  script_cve_id("CVE-2017-7793", "CVE-2017-7805", "CVE-2017-7810", "CVE-2017-7811", "CVE-2017-7812", "CVE-2017-7813", "CVE-2017-7814", "CVE-2017-7815", "CVE-2017-7816", "CVE-2017-7818", "CVE-2017-7819", "CVE-2017-7820", "CVE-2017-7821", "CVE-2017-7822", "CVE-2017-7823", "CVE-2017-7824");
  script_tag(name:"creation_date", value:"2017-10-06 07:15:08 +0000 (Fri, 06 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-3435-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3435-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3435-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1720908");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3435-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3435-1 fixed vulnerabilities in Firefox. The update caused the Flash
plugin to crash in some circumstances. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to read uninitialized memory, obtain sensitive
 information, bypass phishing and malware protection, spoof the origin in
 modal dialogs, conduct cross-site scripting (XSS) attacks, cause a denial
 of service via application crash, or execute arbitrary code.
 (CVE-2017-7793, CVE-2017-7810, CVE-2017-7811, CVE-2017-7812,
 CVE-2017-7813, CVE-2017-7814, CVE-2017-7815, CVE-2017-7818, CVE-2017-7819,
 CVE-2017-7820, CVE-2017-7822, CVE-2017-7823, CVE-2017-7824)

 Martin Thomson discovered that NSS incorrectly generated handshake hashes.
 A remote attacker could potentially exploit this to cause a denial of
 service via application crash, or execute arbitrary code. (CVE-2017-7805)

 Multiple security issues were discovered in WebExtensions. If a user were
 tricked in to installing a specially crafted extension, an attacker could
 potentially exploit these to download and open non-executable files
 without interaction, or obtain elevated privileges. (CVE-2017-7816,
 CVE-2017-7821)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
