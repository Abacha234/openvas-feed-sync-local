# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833493");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-20900");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 13:37:21 +0000 (Wed, 06 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:26:50 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for exempi (SUSE-SU-2023:3835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3835-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AZGBU372U64UNRNX2Y3FU5BJ522LXORR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exempi' package(s) announced via the SUSE-SU-2023:3835-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for open-vm-tools fixes the following issues:

  Update to 12.3.0 (build 22234872) (bsc#1214850)

  * There are no new features in the open-vm-tools 12.3.0 release. This is
      primarily a maintenance release that addresses a few critical problems,
      including:

  * This release integrates CVE-2023-20900 without the need for a patch. For
      more information on this vulnerability and its impact on VMware products,

  * A tools.conf configuration setting is available to temporarily direct Linux
      quiesced snapshots to restore pre open-vm-tools 12.2.0 behavior of ignoring
      file systems already frozen.

  * A number of GitHub issues and pull requests have been handled. Please see
      the Resolves Issues section of the Release Notes.

  * For issues resolved in this release, see the Resolved Issues section of the
      Release Notes.
      tools/releases/tag/stable-12.3.0

  * The granular changes that have gone into the 12.3.0 release are in the
      tools/blob/stable-12.3.0/open-vm-tools/ChangeLog

  * Fix (bsc#1205927) - hv_vmbus module is loaded unnecessarily in VMware guests

  * jsc#PED-1344 - reinable building containerinfo plugin for SLES 15 SP4.");

  script_tag(name:"affected", value:"exempi package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
