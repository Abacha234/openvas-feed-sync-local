# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833327");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-0408", "CVE-2024-0409");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-30 23:03:34 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-03-04 12:55:56 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for xwayland (SUSE-SU-2024:0212-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0212-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MK72ETIY6O7KQLJWS6BN7OQR6ZKUATOS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xwayland'
  package(s) announced via the SUSE-SU-2024:0212-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xwayland fixes the following issues:

  * CVE-2024-0408: Fixed SELinux unlabeled GLX PBuffer. (bsc#1218845)

  * CVE-2024-0409: Fixed SELinux context corruption. (bsc#1218846)

  ##");

  script_tag(name:"affected", value:"'xwayland' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
