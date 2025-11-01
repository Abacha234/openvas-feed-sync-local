# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702732");
  script_cve_id("CVE-2013-2881", "CVE-2013-2882", "CVE-2013-2883", "CVE-2013-2884", "CVE-2013-2885", "CVE-2013-2886");
  script_tag(name:"creation_date", value:"2013-07-30 22:00:00 +0000 (Tue, 30 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2732)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2732");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2732");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2732 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Chromium web browser.

CVE-2013-2881

Karthik Bhargavan discovered a way to bypass the Same Origin Policy in frame handling.

CVE-2013-2882

Cloudfuzzer discovered a type confusion issue in the V8 javascript library.

CVE-2013-2883

Cloudfuzzer discovered a use-after-free issue in MutationObserver.

CVE-2013-2884

Ivan Fratric of the Google Security Team discovered a use-after-free issue in the DOM implementation.

CVE-2013-2885

Ivan Fratric of the Google Security Team discovered a use-after-free issue in input handling.

CVE-2013-2886

The chrome 28 development team found various issues from internal fuzzing, audits, and other studies.

For the stable distribution (wheezy), these problems have been fixed in version 28.0.1500.95-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 28.0.1500.95-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);