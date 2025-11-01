# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.857022");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2022-4904", "CVE-2022-49043");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-14 14:03:27 +0000 (Tue, 14 Mar 2023)");
  script_tag(name:"creation_date", value:"2025-01-31 05:00:33 +0000 (Fri, 31 Jan 2025)");
  script_name("openSUSE: Security Advisory for libxml2 (SUSE-SU-2025:0303-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0303-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OUHOURXU3R3C7N2RI6YRQDLMQTKKFBLT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the SUSE-SU-2025:0303-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxml2 fixes the following issues:

    * CVE-2022-49043: Fixed a use-after-free in xmlXIncludeAddNode. (bsc#1236460)");

  script_tag(name:"affected", value:"'libxml2' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
