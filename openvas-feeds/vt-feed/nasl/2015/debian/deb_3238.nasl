# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703238");
  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248", "CVE-2015-1249", "CVE-2015-3333", "CVE-2015-3334", "CVE-2015-3336");
  script_tag(name:"creation_date", value:"2015-04-25 22:00:00 +0000 (Sat, 25 Apr 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3238)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3238");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3238");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-3238 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in the chromium web browser.

CVE-2015-1235

A Same Origin Policy bypass issue was discovered in the HTML parser.

CVE-2015-1236

Amitay Dobo discovered a Same Origin Policy bypass in the Web Audio API.

CVE-2015-1237

Khalil Zhani discovered a use-after-free issue in IPC.

CVE-2015-1238

cloudfuzzer discovered an out-of-bounds write in the skia library.

CVE-2015-1240

w3bd3vil discovered an out-of-bounds read in the WebGL implementation.

CVE-2015-1241

Phillip Moon and Matt Weston discovered a way to trigger local user interface actions remotely via a crafted website.

CVE-2015-1242

A type confusion issue was discovered in the v8 javascript library.

CVE-2015-1244

Mike Ruddy discovered a way to bypass the HTTP Strict Transport Security policy.

CVE-2015-1245

Khalil Zhani discovered a use-after-free issue in the pdfium library.

CVE-2015-1246

Atte Kettunen discovered an out-of-bounds read issue in webkit/blink.

CVE-2015-1247

Jann Horn discovered that file: URLs in OpenSearch documents were not sanitized, which could allow local files to be read remotely when using the OpenSearch feature from a crafted website.

CVE-2015-1248

Vittorio Gambaletta discovered a way to bypass the SafeBrowsing feature, which could allow the remote execution of a downloaded executable file.

CVE-2015-1249

The chrome 41 development team found various issues from internal fuzzing, audits, and other studies.

CVE-2015-3333

Multiple issues were discovered and fixed in v8 4.2.7.14.

CVE-2015-3334

It was discovered that remote websites could capture video data from attached web cameras without permission.

CVE-2015-3336

It was discovered that remote websites could cause user interface disruptions like window fullscreening and mouse pointer locking.

For the stable distribution (jessie), these problems have been fixed in version 42.0.2311.90-1~deb8u1.

For the testing (stretch) and unstable (sid) distributions, these problems have been fixed in version 42.0.2311.90-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);