# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856737");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-28168");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-27 05:00:20 +0000 (Wed, 27 Nov 2024)");
  script_name("openSUSE: Security Advisory for javapackages (SUSE-SU-2024:4054-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4054-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZNKV5NSPLE4EGK4MDY3EA4QVTHF727VN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'javapackages'
  package(s) announced via the SUSE-SU-2024:4054-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for javapackages-tools, xmlgraphics-batik, xmlgraphics-commons,
  xmlgraphics-fop fixes the following issues:

  xmlgraphics-fop was updated from version 2.8 to 2.10:

  * Security issues fixed:

  * CVE-2024-28168: Fixed improper restriction of XML External Entity (XXE)
      reference (bsc#1231428)

  * Upstream changes and bugs fixed:

  * Version 2.10:

  * footnote-body ignores rl-tb writing mode

  * SVG tspan content is displayed out of place

  * Added new schema to handle pdf/a and pdfa/ua

  * Correct fop version at runtime

  * NoSuchElementException when using font with no family name

  * Resolve classpath for binary distribution

  * Switch to spotbugs

  * Set an automatic module name

  * Rename packages to avoid conflicts with modules

  * Resize table only for multicolumn page

  * Missing jars in servlet

  * Optimise performance of PNG with alpha using raw loader

  * basic-link not navigating to corresponding footnote

  * Added option to sign PDF

  * Added secure processing for XSL input

  * Allow sections which need security permissions to be run when AllPermission denied in caller code

  * Remove unused PDFStructElem

  * Reset content length for table changing ipd

  * Added alt text to PDF signature

  * Allow change of resource level for SVG in AFP

  * Exclude shape not in clipping path for AFP

  * Only support 1 column for redo of layout without page pos only

  * Switch to Jakarta servlet API

  * NPE when list item is split alongside an ipd change

  * Added mandatory MODCA triplet to AFP

  * Redo layout for multipage columns

  * Added image mask option for AFP

  * Skip written block ipds inside float

  * Allow curly braces for src url

  * Missing content for last page with change ipd

  * Added warning when different pdf languages are used

  * Only restart line manager when there is a linebreak for blocklayout

  * Version 2.9:

  * Values in PDF Number Trees must be indirect references

  * Do not delete files on syntax errors using command line

  * Surrogate pair edge-case causes Exception

  * Reset character spacing

  * SVG text containing certain glyphs isn't rendered

  * Remove duplicate classes from maven classpath

  * Allow use of page position only on redo of layout

  * Failure to render multi-block itemBody alongside float

  * Update to PDFBox 2.0.27

  * NPE if link destination is missing with accessibility
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'javapackages' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
