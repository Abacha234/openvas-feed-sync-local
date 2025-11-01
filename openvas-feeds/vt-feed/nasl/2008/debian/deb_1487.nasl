# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60360");
  script_cve_id("CVE-2007-2645", "CVE-2007-6351", "CVE-2007-6352");
  script_tag(name:"creation_date", value:"2008-02-15 22:29:21 +0000 (Fri, 15 Feb 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1487)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1487");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/dsa-1487");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libexif' package(s) announced via the DSA-1487 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the EXIF parsing code of the libexif library, which can lead to denial of service or the execution of arbitrary code if a user is tricked into opening a malformed image. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-2645

Victor Stinner discovered an integer overflow, which may result in denial of service or potentially the execution of arbitrary code.

CVE-2007-6351

Meder Kydyraliev discovered an infinite loop, which may result in denial of service.

CVE-2007-6352

Victor Stinner discovered an integer overflow, which may result in denial of service or potentially the execution of arbitrary code.

This update also fixes two potential NULL pointer deferences.

For the old stable distribution (sarge), these problems have been fixed in 0.6.9-6sarge2.

For the stable distribution (etch), these problems have been fixed in version 0.6.13-5etch2.

We recommend that you upgrade your libexif packages.");

  script_tag(name:"affected", value:"'libexif' package(s) on Debian 3.1, Debian 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);