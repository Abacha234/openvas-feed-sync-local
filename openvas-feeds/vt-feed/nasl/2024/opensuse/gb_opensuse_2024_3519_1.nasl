# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856530");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-8900", "CVE-2024-9392", "CVE-2024-9393", "CVE-2024-9394", "CVE-2024-9396", "CVE-2024-9397", "CVE-2024-9398", "CVE-2024-9399", "CVE-2024-9400", "CVE-2024-9401", "CVE-2024-9402");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-15 16:04:59 +0000 (Tue, 15 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-04 04:01:00 +0000 (Fri, 04 Oct 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2024:3519-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3519-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BXPKEHR77DBH2XSXNUUKH5PSHJO2DNX2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2024:3519-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  Update to Firefox Extended Support Release 128.3.0 ESR (MFSA-2024-47,
  bsc#1230979):

  * CVE-2024-8900: Clipboard write permission bypass

  * CVE-2024-9392: Compromised content process can bypass site isolation

  * CVE-2024-9393: Cross-origin access to PDF contents through multipart
      responses

  * CVE-2024-9394: Cross-origin access to JSON contents through multipart
      responses

  * CVE-2024-9396: Potential memory corruption may occur when cloning certain
      objects

  * CVE-2024-9397: Potential directory upload bypass via clickjacking

  * CVE-2024-9398: External protocol handlers could be enumerated via popups

  * CVE-2024-9399: Specially crafted WebTransport requests could lead to denial
      of service

  * CVE-2024-9400: Potential memory corruption during JIT compilation

  * CVE-2024-9401: Memory safety bugs fixed in Firefox 131, Firefox ESR 115.16,
      Firefox ESR 128.3, Thunderbird 131, and Thunderbird 128.3

  * CVE-2024-9402: Memory safety bugs fixed in Firefox 131, Firefox ESR 128.3,
      Thunderbird 131, and Thunderbird 128.3");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
