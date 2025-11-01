# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702811");
  script_cve_id("CVE-2013-6634", "CVE-2013-6635", "CVE-2013-6636", "CVE-2013-6637", "CVE-2013-6638", "CVE-2013-6639", "CVE-2013-6640", "CVE-2014-1681");
  script_tag(name:"creation_date", value:"2013-12-06 23:00:00 +0000 (Fri, 06 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-2811)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2811");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2811");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'chromium-browser' package(s) announced via the DSA-2811 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2013-6634

Andrey Labunets discovered that the wrong URL was used during validation in the one-click sign on helper.

CVE-2013-6635

cloudfuzzer discovered use-after-free issues in the InsertHTML and Indent DOM editing commands.

CVE-2013-6636

Bas Venis discovered an address bar spoofing issue.

CVE-2013-6637

The chrome 31 development team discovered and fixed multiple issues with potential security impact.

CVE-2013-6638

Jakob Kummerow of the Chromium project discovered a buffer overflow in the v8 javascript library.

CVE-2013-6639

Jakob Kummerow of the Chromium project discovered an out-of-bounds write in the v8 javascript library.

CVE-2013-6640

Jakob Kummerow of the Chromium project discovered an out-of-bounds read in the v8 javascript library.

For the stable distribution (wheezy), these problems have been fixed in version 31.0.1650.63-1~deb7u1.

For the testing distribution (jessie), these problems will be fixed soon.

For the unstable distribution (sid), these problems have been fixed in version 31.0.1650.63-1.

We recommend that you upgrade your chromium-browser packages.");

  script_tag(name:"affected", value:"'chromium-browser' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);