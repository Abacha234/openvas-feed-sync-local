# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886512");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2024-22640");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-05-27 10:42:22 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for php-tcpdf (FEDORA-2024-27eafd0e65)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-27eafd0e65");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/LIB3R2WB7XPW2I4PGVMZ3VLFLRHOK4RB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-tcpdf'
  package(s) announced via the FEDORA-2024-27eafd0e65 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PHP class for generating PDF documents.

  * no external libraries are required for the basic functions,

  * all standard page formats, custom page formats, custom margins and units
  of measure,

  * UTF-8 Unicode and Right-To-Left languages,

  * TrueTypeUnicode, OpenTypeUnicode, TrueType, OpenType, Type1 and CID-0 fonts,

  * font subsetting,

  * methods to publish some XHTML + CSS code, Javascript and Forms,

  * images, graphic (geometric figures) and transformation methods,

  * supports JPEG, PNG and SVG images natively, all images supported by GD
  (GD, GD2, GD2PART, GIF, JPEG, PNG, BMP, XBM, XPM) and all images supported

  * 1D and 2D barcodes: CODE 39, ANSI MH10.8M-1983, USD-3, 3 of 9, CODE 93,
  USS-93, Standard 2 of 5, Interleaved 2 of 5, CODE 128 A/B/C, 2 and 5 Digits
  UPC-Based Extension, EAN 8, EAN 13, UPC-A, UPC-E, MSI, POSTNET, PLANET,
  RMS4CC (Royal Mail 4-state Customer Code), CBC (Customer Bar Code),
  KIX (Klant index - Customer index), Intelligent Mail Barcode, Onecode,
  USPS-B-3200, CODABAR, CODE 11, PHARMACODE, PHARMACODE TWO-TRACKS,
  Datamatrix ECC200, QR-Code, PDF417,

  * ICC Color Profiles, Grayscale, RGB, CMYK, Spot Colors and Transparencies,

  * automatic page header and footer management,

  * document encryption up to 256 bit and digital signature certifications,

  * transactions to UNDO commands,

  * PDF annotations, including links, text and file attachments,

  * text rendering modes (fill, stroke and clipping),

  * multiple columns mode,

  * no-write page regions,

  * bookmarks and table of content,

  * text hyphenation,

  * text stretching and spacing (tracking/kerning),

  * automatic page break, line break and text alignments including justification,

  * automatic page numbering and page groups,

  * move and delete pages,

  * page compression (requires php-zlib extension),

  * XOBject templates,

  * PDF/A-1b (ISO 19005-1:2005) support.

By default, TCPDF uses the GD library which is know as slower than ImageMagick
solution. You can optionally install php-pecl-imagick, TCPDF will use it.");

  script_tag(name:"affected", value:"'php-tcpdf' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
