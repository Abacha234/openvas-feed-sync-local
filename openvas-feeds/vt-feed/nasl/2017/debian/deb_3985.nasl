# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703985");
  script_cve_id("CVE-2017-5111", "CVE-2017-5112", "CVE-2017-5113", "CVE-2017-5114", "CVE-2017-5115", "CVE-2017-5116", "CVE-2017-5117", "CVE-2017-5118", "CVE-2017-5119", "CVE-2017-5120", "CVE-2017-5121", "CVE-2017-5122");
  script_tag(name:"creation_date", value:"2017-09-27 22:00:00 +0000 (Wed, 27 Sep 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-09 02:29:00 +0000 (Sat, 09 Dec 2017)");

  script_name("Debian: Security Advisory (DSA-3985)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3985");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3985");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3985 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2017-5111

Luat Nguyen discovered a use-after-free issue in the pdfium library.

CVE-2017-5112

Tobias Klein discovered a buffer overflow issue in the webgl library.

CVE-2017-5113

A buffer overflow issue was discovered in the skia library.

CVE-2017-5114

Ke Liu discovered a memory issue in the pdfium library.

CVE-2017-5115

Marco Giovannini discovered a type confusion issue in the v8 javascript library.

CVE-2017-5116

Guang Gong discovered a type confusion issue in the v8 javascript library.

CVE-2017-5117

Tobias Klein discovered an uninitialized value in the skia library.

CVE-2017-5118

WenXu Wu discovered a way to bypass the Content Security Policy.

CVE-2017-5119

Another uninitialized value was discovered in the skia library.

CVE-2017-5120

Xiaoyin Liu discovered a way downgrade HTTPS connections during redirection.

CVE-2017-5121

Jordan Rabet discovered an out-of-bounds memory access in the v8 javascript library.

CVE-2017-5122

Choongwoo Han discovered an out-of-bounds memory access in the v8 javascript library.

For the stable distribution (stretch), these problems have been fixed in version 61.0.3163.100-1~deb9u1.

For the testing distribution (buster), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 61.0.3163.100-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);