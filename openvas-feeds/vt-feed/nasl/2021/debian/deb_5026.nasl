# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705026");
  script_cve_id("CVE-2021-38503", "CVE-2021-38504", "CVE-2021-38506", "CVE-2021-38507", "CVE-2021-38508", "CVE-2021-38509", "CVE-2021-4129", "CVE-2021-43534", "CVE-2021-43535", "CVE-2021-43536", "CVE-2021-43537", "CVE-2021-43538", "CVE-2021-43539", "CVE-2021-43541", "CVE-2021-43542", "CVE-2021-43543", "CVE-2021-43545", "CVE-2021-43546");
  script_tag(name:"creation_date", value:"2021-12-20 09:56:41 +0000 (Mon, 20 Dec 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-13 19:53:00 +0000 (Mon, 13 Dec 2021)");

  script_name("Debian: Security Advisory (DSA-5026)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-5026");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5026");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/91.0esr/releasenotes/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firefox-esr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DSA-5026 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web browser, which could potentially result in the execution of arbitrary code, information disclosure or spoofing.

Debian follows the extended support releases (ESR) of Firefox. Support for the 78.x series has ended, so starting with this update we're now following the 91.x releases.

Between 78.x and 91.x, Firefox has seen a number of feature updates. For more information please refer to [link moved to references]

For the oldstable distribution (buster) one more final toolchain update is needed, updated packages will shortly be available as 91.4.1esr-1~deb10u1

For the stable distribution (bullseye), these problems have been fixed in version 91.4.1esr-1~deb11u1.

We recommend that you upgrade your firefox-esr packages.

For the detailed security status of firefox-esr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);