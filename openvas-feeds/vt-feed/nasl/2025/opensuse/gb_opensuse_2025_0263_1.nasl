# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857007");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2024-27029", "CVE-2024-36971", "CVE-2024-36979", "CVE-2024-40920", "CVE-2024-40921", "CVE-2024-41057");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-22 13:38:03 +0000 (Thu, 22 Aug 2024)");
  script_tag(name:"creation_date", value:"2025-01-28 05:06:26 +0000 (Tue, 28 Jan 2025)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (Live Patch 0 for SLE 15 SP6) (SUSE-SU-2025:0263-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0263-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6BSC2IXFYOAWEMUZTPMEX22TS6GD6AJU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel (Live Patch 0 for SLE 15 SP6)'
  package(s) announced via the SUSE-SU-2025:0263-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Linux Kernel 6.4.0-150600_21 fixes several issues.

  The following security issues were fixed:

    * CVE-2024-40921: net: bridge: mst: pass vlan group directly to
      br_mst_vlan_set_state (bsc#1227784).
    * CVE-2024-40920: net: bridge: mst: fix suspicious rcu usage in
      br_mst_set_state (bsc#1227781).
    * CVE-2024-36979: net: bridge: mst: fix vlan use-after-free (bsc#1227369).
    * CVE-2024-41057: cachefiles: fix slab-use-after-free in
      cachefiles_withdraw_cookie() (bsc#1229275).
    * CVE-2024-27029: drm/amdgpu: fix mmhub client id out-of-bounds access
      Properly handle cid 0x140 (bsc#1226184).
    * CVE-2024-36971: Fixed __dst_negative_advice() race (bsc#1226324).");

  script_tag(name:"affected", value:"'the Linux Kernel (Live Patch 0 for SLE 15 SP6)' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
