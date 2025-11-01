# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856145");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-3832", "CVE-2024-3833", "CVE-2024-3834", "CVE-2024-3837", "CVE-2024-3838", "CVE-2024-3839", "CVE-2024-3840", "CVE-2024-3841", "CVE-2024-3843", "CVE-2024-3844", "CVE-2024-3845", "CVE-2024-3846", "CVE-2024-3847", "CVE-2024-3914");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-04-19 17:20:22 +0000 (Fri, 19 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-05-17 01:00:23 +0000 (Fri, 17 May 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2024:0128-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0128-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QVLMJIQMVDQI2D33EDKB65KEXN6OMIRX");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2024:0128-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 110.0.5130.23

  * CHR-9706 Update Chromium on desktop-stable-124-5130 to 124.0.6367.62

  * DNA-116450 Promote 110 to stable

  - The update to chromium 124.0.6367.62 fixes following issues:

       CVE-2024-3832, CVE-2024-3833, CVE-2024-3914, CVE-2024-3834,
     CVE-2024-3837, CVE-2024-3838, CVE-2024-3839, CVE-2024-3840, CVE-2024-3841,
     CVE-2024-3843, CVE-2024-3844, CVE-2024-3845, CVE-2024-3846, CVE-2024-3847

  - Update to 109.0.5097.80

  * DNA-115738 Crash at extensions::ExtensionRegistry::
         GetExtensionById(std::__Cr::basic_string const&, int)

  * DNA-115797 [Flow] Never ending loading while connecting to flow

  * DNA-116315 Chat GPT in Sidebar Panel does not work

  - Update to 109.0.5097.59

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * DNA-115810 Enable #drag-multiple-tabs on all streams

  - Update to 109.0.5097.45

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * DNA-114737 [Search box] It's getting blurred when click
         on it, also lower corners are not rounded sometimes

  * DNA-115042 '+' button is not responsive when 30+ tabs opened

  * DNA-115326 Wrong fonts and padding after intake

  * DNA-115392 [Badges] Text displayed in red

  * DNA-115501 'Review your payment' native popup has wrong colors

  * DNA-115809 Enable #show-duplicate-indicator-on-link on all streams");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.5:NonFree.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
