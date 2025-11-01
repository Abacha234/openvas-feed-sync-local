# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702808");
  script_cve_id("CVE-2013-1447", "CVE-2013-6045", "CVE-2013-6052", "CVE-2013-6054");
  script_tag(name:"creation_date", value:"2013-12-02 23:00:00 +0000 (Mon, 02 Dec 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2808)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-2808");
  script_xref(name:"URL", value:"https://www.debian.org/security/2013/dsa-2808");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openjpeg' package(s) announced via the DSA-2808 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenJPEG, a JPEG 2000 image library, that may lead to denial of service (CVE-2013-1447) via application crash or high memory consumption, possible code execution through heap buffer overflows (CVE-2013-6045), information disclosure (CVE-2013-6052), or yet another heap buffer overflow that only appears to affect OpenJPEG 1.3 (CVE-2013-6054).

For the oldstable distribution (squeeze), these problems have been fixed in version 1.3+dfsg-4+squeeze2.

For the stable distribution (wheezy), these problems have been fixed in version 1.3+dfsg-4.7.

For the testing distribution (jessie), and the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your openjpeg packages.");

  script_tag(name:"affected", value:"'openjpeg' package(s) on Debian 6, Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);