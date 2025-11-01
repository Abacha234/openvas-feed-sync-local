# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856780");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-11233", "CVE-2024-11234", "CVE-2024-8929");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-26 18:26:37 +0000 (Tue, 26 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-12-04 05:00:25 +0000 (Wed, 04 Dec 2024)");
  script_name("openSUSE: Security Advisory for php7 (SUSE-SU-2024:4146-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4146-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HMOXG4E2RC32BG25BX3ZIJYTSY4KFSU3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7'
  package(s) announced via the SUSE-SU-2024:4146-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php7 fixes the following issues:

  * CVE-2024-11233: Single byte overread with convert.quoted-printable-decode
      filter (bsc#1233702).

  * CVE-2024-11234: Configuring a proxy in a stream context might allow for CRLF
      injection in URIs (bsc#1233703).

  * CVE-2024-8929: Leak partial content of the heap through heap buffer over-
      read (bsc#1233651).");

  script_tag(name:"affected", value:"'php7' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
