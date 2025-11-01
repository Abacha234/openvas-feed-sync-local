# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703762");
  script_cve_id("CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10094", "CVE-2016-10271", "CVE-2016-10272", "CVE-2016-3622", "CVE-2016-3623", "CVE-2016-3624", "CVE-2016-3945", "CVE-2016-3990", "CVE-2016-3991", "CVE-2016-5314", "CVE-2016-5315", "CVE-2016-5316", "CVE-2016-5317", "CVE-2016-5321", "CVE-2016-5322", "CVE-2016-5323", "CVE-2016-5652", "CVE-2016-6223", "CVE-2016-9273", "CVE-2016-9297", "CVE-2016-9453", "CVE-2016-9532", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9536", "CVE-2016-9537", "CVE-2016-9538", "CVE-2016-9540");
  script_tag(name:"creation_date", value:"2017-01-12 23:00:00 +0000 (Thu, 12 Jan 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");

  script_name("Debian: Security Advisory (DSA-3762)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3762");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3762");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'tiff' package(s) announced via the DSA-3762 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the libtiff library and the included tools tiff2rgba, rgb2ycbcr, tiffcp, tiffcrop, tiff2pdf and tiffsplit, which may result in denial of service, memory disclosure or the execution of arbitrary code.

There were additional vulnerabilities in the tools bmp2tiff, gif2tiff, thumbnail and ras2tiff, but since these were addressed by the libtiff developers by removing the tools altogether, no patches are available and those tools were also removed from the tiff package in Debian stable. The change had already been made in Debian stretch before and no applications included in Debian are known to rely on these scripts. If you use those tools in custom setups, consider using a different conversion/thumbnailing tool.

For the stable distribution (jessie), these problems have been fixed in version 4.0.3-12.3+deb8u2.

For the testing distribution (stretch), these problems have been fixed in version 4.0.7-4.

For the unstable distribution (sid), these problems have been fixed in version 4.0.7-4.

We recommend that you upgrade your tiff packages.");

  script_tag(name:"affected", value:"'tiff' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);