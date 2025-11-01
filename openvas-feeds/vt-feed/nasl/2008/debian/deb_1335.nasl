# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58467");
  script_cve_id("CVE-2006-4519", "CVE-2007-2949");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1335)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1335");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/dsa-1335");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gimp' package(s) announced via the DSA-1335 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Gimp, the GNU Image Manipulation Program, which might lead to the execution of arbitrary code. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2006-4519

Sean Larsson discovered several integer overflows in the processing code for DICOM, PNM, PSD, RAS, XBM and XWD images, which might lead to the execution of arbitrary code if a user is tricked into opening such a malformed media file.

CVE-2007-2949

Stefan Cornelius discovered an integer overflow in the processing code for PSD images, which might lead to the execution of arbitrary code if a user is tricked into opening such a malformed media file.

For the oldstable distribution (sarge) these problems have been fixed in version 2.2.6-1sarge4. Packages for mips and mipsel are not yet available.

For the stable distribution (etch) these problems have been fixed in version 2.2.13-1etch4. Packages for mips are not yet available.

For the unstable distribution (sid) these problems have been fixed in version 2.2.17-1.

We recommend that you upgrade your gimp packages.");

  script_tag(name:"affected", value:"'gimp' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);