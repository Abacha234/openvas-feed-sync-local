# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833312");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-23517", "CVE-2022-23518", "CVE-2022-23519", "CVE-2022-23520");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-16 19:13:24 +0000 (Fri, 16 Dec 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 07:50:24 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rubygem (SUSE-SU-2023:3714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3714-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/V6OPT76VYMAHMC2QYM7QQ3EXEZEISEAL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem'
  package(s) announced via the SUSE-SU-2023:3714-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-rails-html-sanitizer fixes the following issues:

  * CVE-2022-23517: Fixed inefficient regular expression that is susceptible to
      excessive backtracking when attempting to sanitize certain SVG attributes.
      (bsc#1206433)

  * CVE-2022-23518: Fixed XSS via data URIs when used in combination with
      Loofah. (bsc#1206434)

  * CVE-2022-23519: Fixed XSS vulnerability with certain configurations of
      Rails::Html::Sanitizer. (bsc#1206435)

  * CVE-2022-23520: Fixed XSS vulnerability with certain configurations of
      Rails::Html::Sanitizer. (bsc#1206436)

  ##");

  script_tag(name:"affected", value:"'rubygem' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
