# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702724");
  script_cve_id("CVE-2013-2853", "CVE-2013-2867", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870", "CVE-2013-2871", "CVE-2013-2873", "CVE-2013-2875", "CVE-2013-2876", "CVE-2013-2877", "CVE-2013-2878", "CVE-2013-2879", "CVE-2013-2880");
  script_tag(name:"creation_date", value:"2013-07-16 22:00:00 +0000 (Tue, 16 Jul 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2724)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2724");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2724");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2724 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Chromium web browser.

CVE-2013-2853

The HTTPS implementation does not ensure that headers are terminated by rnrn (carriage return, newline, carriage return, newline).

CVE-2013-2867

Chrome does not properly prevent pop-under windows.

CVE-2013-2868

common/extensions/sync_helper.cc proceeds with sync operations for NPAPI extensions without checking for a certain plugin permission setting.

CVE-2013-2869

Denial of service (out-of-bounds read) via a crafted JPEG2000 image.

CVE-2013-2870

Use-after-free vulnerability in network sockets.

CVE-2013-2871

Use-after-free vulnerability in input handling.

CVE-2013-2873

Use-after-free vulnerability in resource loading.

CVE-2013-2875

Out-of-bounds read in SVG file handling.

CVE-2013-2876

Chromium does not properly enforce restrictions on the capture of screenshots by extensions, which could lead to information disclosure from previous page visits.

CVE-2013-2877

Out-of-bounds read in XML file handling.

CVE-2013-2878

Out-of-bounds read in text handling.

CVE-2013-2879

The circumstances in which a renderer process can be considered a trusted process for sign-in and subsequent sync operations were not properly checked.

CVE-2013-2880

The Chromium 28 development team found various issues from internal fuzzing, audits, and other studies.

For the stable distribution (wheezy), these problems have been fixed in version 28.0.1500.71-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 28.0.1500.71-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);