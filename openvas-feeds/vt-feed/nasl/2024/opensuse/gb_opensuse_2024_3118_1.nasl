# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856429");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-23184", "CVE-2024-2318", "CVE-2024-23185");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-09-06 04:01:05 +0000 (Fri, 06 Sep 2024)");
  script_name("openSUSE: Security Advisory for dovecot23 (SUSE-SU-2024:3118-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3118-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/JQSFCWVTCFHTGKF2O6MI24G3B4URVH33");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot23'
  package(s) announced via the SUSE-SU-2024:3118-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for dovecot23 fixes the following issues:

  * CVE-2024-23185: Fixed a denial of service with large headers (bsc#1229183)

  * CVE-2024-23184: Fixed a denial of service parsing messages containing many
      address headers (bsc#1229184)

  ##");

  script_tag(name:"affected", value:"'dovecot23' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
