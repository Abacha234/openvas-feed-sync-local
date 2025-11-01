# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833688");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-17 18:55:23 +0000 (Fri, 17 Feb 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:41:54 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for rubygem (SUSE-SU-2023:0276-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0276-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FJFU3ZHNAUDV7V7P7HFAAT4TJIHOMW5K");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rubygem'
  package(s) announced via the SUSE-SU-2023:0276-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rubygem-rack fixes the following issues:

  - CVE-2022-44570: Fixed a potential denial of service when parsing a
       RFC2183 multipart boundary (bsc#1207597).

  - CVE-2022-44571: Fixed a potential denial of service when parsing a Range
       header (bsc#1207599).

  - CVE-2022-44572: Fixed a potential denial of service when parsing a
       Content-Disposition header (bsc#1207596).");

  script_tag(name:"affected", value:"'rubygem' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
