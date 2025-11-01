# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702741");
  script_cve_id("CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902", "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905");
  script_tag(name:"creation_date", value:"2013-08-24 22:00:00 +0000 (Sat, 24 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2741)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2741");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2741");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2741 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Chromium web browser.

CVE-2013-2887

The chrome 29 development team found various issues from internal fuzzing, audits, and other studies.

CVE-2013-2900

Krystian Bigaj discovered a file handling path sanitization issue.

CVE-2013-2901

Alex Chapman discovered an integer overflow issue in ANGLE, the Almost Native Graphics Layer.

CVE-2013-2902

cloudfuzzer discovered a use-after-free issue in XSLT.

CVE-2013-2903

cloudfuzzer discovered a use-after-free issue in HTMLMediaElement.

CVE-2013-2904

cloudfuzzer discovered a use-after-free issue in XML document parsing.

CVE-2013-2905

Christian Jaeger discovered an information leak due to insufficient file permissions.

For the stable distribution (wheezy), these problems have been fixed in version 29.0.1547.57-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 29.0.1547.57-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);