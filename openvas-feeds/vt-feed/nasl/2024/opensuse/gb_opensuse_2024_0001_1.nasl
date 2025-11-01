# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833739");
  script_version("2025-02-26T05:38:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-6702", "CVE-2023-6703", "CVE-2023-6704", "CVE-2023-6705", "CVE-2023-6706", "CVE-2023-6707", "CVE-2023-7024");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-27 20:48:22 +0000 (Wed, 27 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 12:52:33 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for opera (openSUSE-SU-2024:0001-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0001-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B42PNFAINV67T2VV3ZZUOTVQ44CXKXM6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opera'
  package(s) announced via the openSUSE-SU-2024:0001-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for opera fixes the following issues:

  - Update to 106.0.4998.19

  * CHR-9416 Updating Chromium on desktop-stable-* branches

  * DNA-113887 Translations for O106

  - The update to chromium 120.0.6099.130 fixes following issues:
       CVE-2023-7024

  - Update to 106.0.4998.16

  * CHR-9553 Update Chromium on desktop-stable-120-4998 to 120.0.6099.109

  * DNA-112522 'Find in page' option does not show text cursor

  * DNA-113349 Lucid mode strength in full settings bar is visible only
         after change

  * DNA-113462 Crash at opera::fcm::FcmRegistrationServiceImpl::
         RemoveTokenObserverForClient(opera::fcm::FcmClient*,
         syncer::FCMRegistrationTokenObserver*)

  * DNA-113748 Split preview shows on videoconferencing

  * DNA-114091 Promote 106 to stable

  - Complete Opera 106 changelog at:
       CVE-2023-6702, CVE-2023-6703, CVE-2023-6704, CVE-2023-6705,
       CVE-2023-6706, CVE-2023-6707

  - Update to 105.0.4970.48

  * DNA-112522 'Find in page' option does not show text cursor");

  script_tag(name:"affected", value:"'opera' package(s) on openSUSE Leap 15.4:NonFree.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
