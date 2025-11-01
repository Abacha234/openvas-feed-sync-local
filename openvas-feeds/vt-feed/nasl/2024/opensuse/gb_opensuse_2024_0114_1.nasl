# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856110");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-25583");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-04-30 01:00:21 +0000 (Tue, 30 Apr 2024)");
  script_name("openSUSE: Security Advisory for pdns (openSUSE-SU-2024:0114-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0114-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZZH2ONXJKWNVDG6IH66D5CLFDU6CHDXI");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pdns'
  package(s) announced via the openSUSE-SU-2024:0114-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for pdns-recursor fixes the following issues:

  - update to 4.8.8:

  * fixes a case when a crafted responses can lead to a denial of service
         in Recursor if recursive forwarding is configured (boo#1223262,
         CVE-2024-25583)

  - changes in 4.8.7:

  * If serving stale, wipe CNAME records from cache when we get a NODATA
         negative response for them

  * Fix the zoneToCache regression introduced by last security update");

  script_tag(name:"affected", value:"'pdns' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
