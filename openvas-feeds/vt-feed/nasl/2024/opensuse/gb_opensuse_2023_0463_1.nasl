# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833667");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-48303");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-30 17:16:57 +0000 (Tue, 30 May 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:25:28 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for tar (SUSE-SU-2023:0463-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0463-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/EMCL5SDDZC2JTGVOT5D2T56IWCRICHJD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tar'
  package(s) announced via the SUSE-SU-2023:0463-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for tar fixes the following issues:

  - CVE-2022-48303: Fixed a one-byte out-of-bounds read that resulted in use
       of uninitialized memory for a conditional jump (bsc#1207753).

     Bug fixes:

  - Fix hang when unpacking test tarball (bsc#1202436).");

  script_tag(name:"affected", value:"'tar' package(s) on openSUSE Leap 15.4, openSUSE Leap Micro 5.2, openSUSE Leap Micro 5.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
