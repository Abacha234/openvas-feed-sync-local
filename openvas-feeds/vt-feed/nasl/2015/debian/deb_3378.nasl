# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703378");
  script_cve_id("CVE-2015-7673", "CVE-2015-7674");
  script_tag(name:"creation_date", value:"2015-10-23 22:00:00 +0000 (Fri, 23 Oct 2015)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-3378)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3378");
  script_xref(name:"URL", value:"https://www.debian.org/security/2015/dsa-3378");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gdk-pixbuf' package(s) announced via the DSA-3378 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in gdk-pixbuf, a toolkit for image loading and pixel buffer manipulation. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2015-7673

Gustavo Grieco discovered a heap overflow in the processing of TGA images which may result in the execution of arbitrary code or denial of service (process crash) if a malformed image is opened.

CVE-2015-7674

Gustavo Grieco discovered an integer overflow flaw in the processing of GIF images which may result in the execution of arbitrary code or denial of service (process crash) if a malformed image is opened.

For the oldstable distribution (wheezy), these problems have been fixed in version 2.26.1-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed in version 2.31.1-2+deb8u3.

For the testing distribution (stretch), these problems have been fixed in version 2.32.1-1 or earlier.

For the unstable distribution (sid), these problems have been fixed in version 2.32.1-1 or earlier.

We recommend that you upgrade your gdk-pixbuf packages.");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on Debian 7, Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);