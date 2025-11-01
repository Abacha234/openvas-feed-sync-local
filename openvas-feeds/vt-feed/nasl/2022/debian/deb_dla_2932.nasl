# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892932");
  script_cve_id("CVE-2022-0561", "CVE-2022-0562", "CVE-2022-22844");
  script_tag(name:"creation_date", value:"2022-03-07 02:00:07 +0000 (Mon, 07 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-19 15:50:00 +0000 (Wed, 19 Jan 2022)");

  script_name("Debian: Security Advisory (DLA-2932)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DLA-2932");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/dla-2932");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/tiff");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DLA-2932 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issues have been found in tiff, a library and tools to manipulate and convert files in the Tag Image File Format (TIFF).

CVE-2022-22844

out-of-bounds read in _TIFFmemcpy in certain situations involving a custom tag and 0x0200 as the second word of the DE field.

CVE-2022-0562

Null source pointer passed as an argument to memcpy() function within TIFFReadDirectory(). This could result in a Denial of Service via crafted TIFF files.

CVE-2022-0561

Null source pointer passed as an argument to memcpy() function within TIFFFetchStripThing(). This could result in a Denial of Service via crafted TIFF files.

For Debian 9 stretch, these problems have been fixed in version 4.0.8-2+deb9u8.

We recommend that you upgrade your tiff packages.

For the detailed security status of tiff please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);