# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833164");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-4091", "CVE-2023-4154", "CVE-2023-42669");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-14 18:20:56 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 08:02:11 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for samba (SUSE-SU-2023:4059-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4059-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4MRU7OVHQ4LLWDWQMXD72ME5ZVLFEJCV");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the SUSE-SU-2023:4059-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

  * CVE-2023-4091: Fixed a bug where a client can truncate file with read-only
      permissions. (bsc#1215904)

  * CVE-2023-42669: Fixed a bug in 'rpcecho' development server which allows
      Denial of Service via sleep() call on AD DC. (bso#1215905)

  * CVE-2023-4154: Fixed a bug in dirsync which allows SYSTEM access with only
      'GUID_DRS_GET_CHANGES' right. (bsc#1215908)

  ##");

  script_tag(name:"affected", value:"'samba' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
