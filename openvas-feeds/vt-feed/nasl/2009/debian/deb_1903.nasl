# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.65746");
  script_cve_id("CVE-2007-1667", "CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-3134", "CVE-2008-6070", "CVE-2008-6071", "CVE-2008-6072", "CVE-2008-6621", "CVE-2009-1882");
  script_tag(name:"creation_date", value:"2009-10-13 16:25:40 +0000 (Tue, 13 Oct 2009)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1903)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-1903");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/dsa-1903");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'graphicsmagick' package(s) announced via the DSA-1903 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in graphicsmagick, a collection of image processing tool, which can lead to the execution of arbitrary code, exposure of sensitive information or cause DoS. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1667

Multiple integer overflows in XInitImage function in xwd.c for GraphicsMagick, allow user-assisted remote attackers to cause a denial of service (crash) or obtain sensitive information via crafted images with large or negative values that trigger a buffer overflow. It only affects the oldstable distribution (etch).

CVE-2007-1797

Multiple integer overflows allow remote attackers to execute arbitrary code via a crafted DCM image, or the colors or comments field in a crafted XWD image. It only affects the oldstable distribution (etch).

CVE-2007-4985

A crafted image file can trigger an infinite loop in the ReadDCMImage function or in the ReadXCFImage function. It only affects the oldstable distribution (etch).

CVE-2007-4986

Multiple integer overflows allow context-dependent attackers to execute arbitrary code via a crafted .dcm, .dib, .xbm, .xcf, or .xwd image file, which triggers a heap-based buffer overflow. It only affects the oldstable distribution (etch).

CVE-2007-4988

A sign extension error allows context-dependent attackers to execute arbitrary code via a crafted width value in an image file, which triggers an integer overflow and a heap-based buffer overflow. It affects only the oldstable distribution (etch).

CVE-2008-1096

The load_tile function in the XCF coder allows user-assisted remote attackers to cause a denial of service or possibly execute arbitrary code via a crafted .xcf file that triggers an out-of-bounds heap write. It affects only oldstable (etch).

CVE-2008-3134

Multiple vulnerabilities in GraphicsMagick before 1.2.4 allow remote attackers to cause a denial of service (crash, infinite loop, or memory consumption) via vectors in the AVI, AVS, DCM, EPT, FITS, MTV, PALM, RLA, and TGA decoder readers, and the GetImageCharacteristics function in magick/image.c, as reachable from a crafted PNG, JPEG, BMP, or TIFF file.

CVE-2008-6070

Multiple heap-based buffer underflows in the ReadPALMImage function in coders/palm.c in GraphicsMagick before 1.2.3 allow remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted PALM image.

CVE-2008-6071

Heap-based buffer overflow in the DecodeImage function in coders/pict.c in GraphicsMagick before 1.1.14, and 1.2.x before 1.2.3, allows remote attackers to cause a denial of service (crash) or possibly execute arbitrary code via a crafted PICT image.

CVE-2008-6072

Multiple vulnerabilities in GraphicsMagick allow remote attackers to cause a denial of service (crash) via vectors in XCF and CINEON images.

CVE-2008-6621

Vulnerability in GraphicsMagick allows remote ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'graphicsmagick' package(s) on Debian 4, Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);