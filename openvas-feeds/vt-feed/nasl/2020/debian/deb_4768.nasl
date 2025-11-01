# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704768");
  script_cve_id("CVE-2020-15673", "CVE-2020-15676", "CVE-2020-15677", "CVE-2020-15678");
  script_tag(name:"creation_date", value:"2020-09-30 03:00:07 +0000 (Wed, 30 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-02 21:15:00 +0000 (Mon, 02 Nov 2020)");

  script_name("Debian: Security Advisory (DSA-4768)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4768");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4768");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/78.0esr/releasenotes/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/firefox-esr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'firefox-esr' package(s) announced via the DSA-4768 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web browser, which could potentially result in the execution of arbitrary code, cross-site scripting or spoofing the origin of a download.

Debian follows the extended support releases (ESR) of Firefox. Support for the 68.x series has ended, so starting with this update we're now following the 78.x releases.

Between 68.x and 78.x, Firefox has seen a number of feature updates. For more information please refer to [link moved to references]

For the stable distribution (buster), these problems have been fixed in version 78.3.0esr-1~deb10u1.

We recommend that you upgrade your firefox-esr packages.

For the detailed security status of firefox-esr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);