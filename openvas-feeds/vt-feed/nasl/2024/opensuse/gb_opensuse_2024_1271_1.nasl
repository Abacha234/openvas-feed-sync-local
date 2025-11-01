# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856069");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-28834", "CVE-2024-28835");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-03-21 14:15:07 +0000 (Thu, 21 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-04-17 01:01:07 +0000 (Wed, 17 Apr 2024)");
  script_name("openSUSE: Security Advisory for gnutls (SUSE-SU-2024:1271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:1271-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/73NM5RQ5EKED3TTANECGCQ3YWM3KOOX5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls'
  package(s) announced via the SUSE-SU-2024:1271-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnutls fixes the following issues:

  * CVE-2024-28834: Fixed side-channel in the deterministic ECDSA (bsc#1221746)

  * CVE-2024-28835: Fixed denial of service during certificate chain
      verification (bsc#1221747)

  Other fixes: \- jitterentropy: Release the memory of the entropy collector when
  using jitterentropy with  pthreads as there is also a pre-intitization done in
  the main thread (bsc#1221242)

  ##");

  script_tag(name:"affected", value:"'gnutls' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap Micro 5.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
