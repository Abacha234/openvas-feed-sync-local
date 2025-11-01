# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703776");
  script_cve_id("CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009", "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013", "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017", "CVE-2017-5018", "CVE-2017-5019", "CVE-2017-5020", "CVE-2017-5021", "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025", "CVE-2017-5026", "CVE-2017-5027", "CVE-2017-5028");
  script_tag(name:"creation_date", value:"2017-02-03 06:41:15 +0000 (Fri, 03 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3776)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3776");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3776");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3776 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2017-5006

Mariusz Mlynski discovered a cross-site scripting issue.

CVE-2017-5007

Mariusz Mlynski discovered another cross-site scripting issue.

CVE-2017-5008

Mariusz Mlynski discovered a third cross-site scripting issue.

CVE-2017-5009

Sean Stanek and Chip Bradford discovered an out-of-bounds memory issue in the webrtc library.

CVE-2017-5010

Mariusz Mlynski discovered a fourth cross-site scripting issue.

CVE-2017-5011

Khalil Zhani discovered a way to access unauthorized files in the developer tools.

CVE-2017-5012

Gergely Nagy discovered a heap overflow issue in the v8 javascript library.

CVE-2017-5013

Haosheng Wang discovered a URL spoofing issue.

CVE-2017-5014

sweetchip discovered a heap overflow issue in the skia library.

CVE-2017-5015

Armin Razmdjou discovered a URL spoofing issue.

CVE-2017-5016

Haosheng Wang discovered another URL spoofing issue.

CVE-2017-5017

danberm discovered an uninitialized memory issue in support for webm video files.

CVE-2017-5018

Rob Wu discovered a cross-site scripting issue.

CVE-2017-5019

Wadih Matar discovered a use-after-free issue.

CVE-2017-5020

Rob Wu discovered another cross-site scripting issue.

CVE-2017-5021

Rob Wu discovered a use-after-free issue in extensions.

CVE-2017-5022

PKAV Team discovered a way to bypass the Content Security Policy.

CVE-2017-5023

UK's National Cyber Security Centre (NCSC) discovered a type confusion issue.

CVE-2017-5024

Paul Mehta discovered a heap overflow issue in the ffmpeg library.

CVE-2017-5025

Paul Mehta discovered another heap overflow issue in the ffmpeg library.

CVE-2017-5026

Ronni Skansing discovered a user interface spoofing issue.

For the stable distribution (jessie), these problems have been fixed in version 56.0.2924.76-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems will be fixed soon.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);