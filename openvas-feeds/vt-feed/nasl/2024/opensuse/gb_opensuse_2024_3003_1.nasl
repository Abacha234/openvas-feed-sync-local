# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856391");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-6600", "CVE-2024-6601", "CVE-2024-6602", "CVE-2024-6603", "CVE-2024-6604", "CVE-2024-6605", "CVE-2024-6606", "CVE-2024-6607", "CVE-2024-6608", "CVE-2024-6609", "CVE-2024-6610", "CVE-2024-6611", "CVE-2024-6612", "CVE-2024-6613", "CVE-2024-6614", "CVE-2024-6615", "CVE-2024-7518", "CVE-2024-7519", "CVE-2024-7520", "CVE-2024-7521", "CVE-2024-7522", "CVE-2024-7524", "CVE-2024-7525", "CVE-2024-7526", "CVE-2024-7527", "CVE-2024-7528", "CVE-2024-7529", "CVE-2024-7531");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-12 16:04:20 +0000 (Mon, 12 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-08-28 04:00:48 +0000 (Wed, 28 Aug 2024)");
  script_name("openSUSE: Security Advisory for MozillaFirefox (SUSE-SU-2024:3003-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3003-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/DLHFAHB76P6C3SXIM2TSUIMIWQBJF4XJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaFirefox'
  package(s) announced via the SUSE-SU-2024:3003-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for MozillaFirefox fixes the following issues:

  Update to Firefox Extended Support Release 128.1.0 ESR (MFSA 2024-35,
  bsc#1228648) \- CVE-2024-7518: Fullscreen notification dialog can be obscured by
  document \- CVE-2024-7519: Out of bounds memory access in graphics shared memory
  handling \- CVE-2024-7520: Type confusion in WebAssembly \- CVE-2024-7521:
  Incomplete WebAssembly exception handing \- CVE-2024-7522: Out of bounds read in
  editor component \- CVE-2024-7524: CSP strict-dynamic bypass using web-
  compatibility shims \- CVE-2024-7525: Missing permission check when creating a
  StreamFilter \- CVE-2024-7526: Uninitialized memory used by WebGL \-
  CVE-2024-7527: Use-after-free in JavaScript garbage collection \- CVE-2024-7528:
  Use-after-free in IndexedDB \- CVE-2024-7529: Document content could partially
  obscure security prompts \- CVE-2024-7531: PK11_Encrypt using CKM_CHACHA20 can
  reveal plaintext on Intel");

  script_tag(name:"affected", value:"'MozillaFirefox' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
