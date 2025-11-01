# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856545");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2015-8981", "CVE-2017-6840", "CVE-2017-6841", "CVE-2017-6842", "CVE-2017-6845", "CVE-2017-6849", "CVE-2017-8378", "CVE-2018-5309", "CVE-2018-8001");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-10 17:30:42 +0000 (Wed, 10 May 2017)");
  script_tag(name:"creation_date", value:"2024-10-09 04:03:29 +0000 (Wed, 09 Oct 2024)");
  script_name("openSUSE: Security Advisory for podofo (SUSE-SU-2024:3550-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3550-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2GWIRZHT3JTAA33TPFFMMQWIJ5DDDPWH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podofo'
  package(s) announced via the SUSE-SU-2024:3550-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podofo fixes the following issues:

  * CVE-2015-8981: Fixed heap overflow in the function ReadXRefSubsection
      (bsc#1023190)

  * CVE-2017-6840: Fixed invalid memory read in ColorChanger::GetColorFromStack
      (colorchanger.cpp) (bsc#1027787)

  * CVE-2017-6841: Fixed NULL pointer dereference in
      GraphicsStack::TGraphicsStackElement::~TGraphicsStackElement
      (graphicsstack.h) (bsc#1027786)

  * CVE-2017-6842: Fixed NULL pointer dereference in
      ColorChanger::GetColorFromStack (colorchanger.cpp) (bsc#1027785)

  * CVE-2017-6845: Fixed NULL pointer dereference in
      GraphicsStack::TGraphicsStackElement::SetNonStrokingColorSpace
      (graphicsstack.h) (bsc#1027779)

  * CVE-2017-6849: Fixed NULL pointer dereference in
      PoDoFo::PdfColorGray::~PdfColorGray (PdfColor.cpp) (bsc#1027776)

  * CVE-2017-8378: Fixed denial of service (application crash) vectors related
      to m_offsets.size (PdfParser::ReadObjects func in base/PdfParser.cpp)
      (bsc#1037000)

  * Fixed NULL pointer dereference in PdfInfo::GuessFormat (pdfinfo.cpp)
      (bsc#1023072)");

  script_tag(name:"affected", value:"'podofo' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
