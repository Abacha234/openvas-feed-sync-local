# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.704858");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-21148", "CVE-2021-21149", "CVE-2021-21150", "CVE-2021-21151", "CVE-2021-21152", "CVE-2021-21153", "CVE-2021-21154", "CVE-2021-21155", "CVE-2021-21156", "CVE-2021-21157");
  script_tag(name:"creation_date", value:"2021-02-21 04:00:11 +0000 (Sun, 21 Feb 2021)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-01 02:15:00 +0000 (Sat, 01 May 2021)");

  script_name("Debian: Security Advisory (DSA-4858)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-4858");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4858");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium' package(s) announced via the DSA-4858 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2021-21148

Mattias Buelens discovered a buffer overflow issue in the v8 javascript library.

CVE-2021-21149

Ryoya Tsukasaki discovered a stack overflow issue in the Data Transfer implementation.

CVE-2021-21150

Woojin Oh discovered a use-after-free issue in the file downloader.

CVE-2021-21151

Khalil Zhani discovered a use-after-free issue in the payments system.

CVE-2021-21152

A buffer overflow was discovered in media handling.

CVE-2021-21153

Jan Ruge discovered a stack overflow issue in the GPU process.

CVE-2021-21154

Abdulrahman Alqabandi discovered a buffer overflow issue in the Tab Strip implementation.

CVE-2021-21155

Khalil Zhani discovered a buffer overflow issue in the Tab Strip implementation.

CVE-2021-21156

Sergei Glazunov discovered a buffer overflow issue in the v8 javascript library.

CVE-2021-21157

A use-after-free issue was discovered in the Web Sockets implementation.

For the stable distribution (buster), these problems have been fixed in version 88.0.4324.182-1~deb10u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian 10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);