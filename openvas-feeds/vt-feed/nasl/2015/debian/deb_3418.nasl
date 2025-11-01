# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703418");
  script_cve_id("CVE-2015-6788", "CVE-2015-6789", "CVE-2015-6790", "CVE-2015-6791", "CVE-2015-8548");
  script_tag(name:"creation_date", value:"2015-12-13 23:00:00 +0000 (Sun, 13 Dec 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-3418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3418");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3418");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2015-6788

A type confusion issue was discovered in the handling of extensions.

CVE-2015-6789

cloudfuzzer discovered a use-after-free issue.

CVE-2015-6790

Inti De Ceukelaire discovered a way to inject HTML into serialized web pages.

CVE-2015-6791

The chrome 47 development team found and fixed various issues during internal auditing. Also multiple issues were fixed in the v8 javascript library, version 4.7.80.23.

For the stable distribution (jessie), these problems have been fixed in version 47.0.2526.80-1~deb8u1.

For the testing distribution (stretch), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 47.0.2526.80-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);