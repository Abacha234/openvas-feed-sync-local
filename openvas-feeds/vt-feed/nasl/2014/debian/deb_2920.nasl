# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702920");
  script_cve_id("CVE-2014-1730", "CVE-2014-1731", "CVE-2014-1732", "CVE-2014-1733", "CVE-2014-1734", "CVE-2014-1735", "CVE-2014-1736");
  script_tag(name:"creation_date", value:"2014-05-02 22:00:00 +0000 (Fri, 02 May 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-2920)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2920");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/dsa-2920");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2920 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2014-1730

A type confusion issue was discovered in the v8 javascript library.

CVE-2014-1731

John Butler discovered a type confusion issue in the WebKit/Blink document object model implementation.

CVE-2014-1732

Khalil Zhani discovered a use-after-free issue in the speech recognition feature.

CVE-2014-1733

Jed Davis discovered a way to bypass the seccomp-bpf sandbox.

CVE-2014-1734

The Google Chrome development team discovered and fixed multiple issues with potential security impact.

CVE-2014-1735

The Google Chrome development team discovered and fixed multiple issues in version 3.24.35.33 of the v8 javascript library.

CVE-2014-1736

SkyLined discovered an integer overflow issue in the v8 javascript library.

For the stable distribution (wheezy), these problems have been fixed in version 34.0.1847.132-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 34.0.1847.132-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);