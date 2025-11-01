# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856228");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-3049");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 17:54:22 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-19 04:00:26 +0000 (Wed, 19 Jun 2024)");
  script_name("openSUSE: Security Advisory for booth (SUSE-SU-2024:2040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2040-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PVHVYWPKCQW3URYL7BW5DUFG4RH3GM7W");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'booth'
  package(s) announced via the SUSE-SU-2024:2040-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for booth fixes the following issues:

  * CVE-2024-3049: Fixed a vulnerability where a specially crafted hash can lead
      to invalid HMAC being accepted by Booth server. (bsc#1226032)

  ##");

  script_tag(name:"affected", value:"'booth' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
