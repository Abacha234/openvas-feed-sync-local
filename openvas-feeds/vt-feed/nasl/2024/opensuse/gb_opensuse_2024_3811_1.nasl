# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856638");
  script_version("2025-03-11T05:38:16+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-03-11 05:38:16 +0000 (Tue, 11 Mar 2025)");
  script_tag(name:"creation_date", value:"2024-10-31 05:01:05 +0000 (Thu, 31 Oct 2024)");
  script_name("openSUSE: Security Advisory for govulncheck (SUSE-SU-2024:3811-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3811-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AHT2C7QHW4QSM4BHRDKRWG63ED4H6YYN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'govulncheck'
  package(s) announced via the SUSE-SU-2024:3811-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for govulncheck-vulndb fixes the following issues:

  * Update to version 0.0.20241028T152002 2024-10-28T15:20:02Z. Refs
      jsc#PED-11136 Go CVE Numbering Authority IDs added or updated:

  * GO-2024-3207

  * GO-2024-3208

  * GO-2024-3210

  * GO-2024-3211

  * GO-2024-3212

  * GO-2024-3213

  * GO-2024-3214

  * GO-2024-3215

  * GO-2024-3216

  * GO-2024-3217

  * GO-2024-3219

  * GO-2024-3220

  * GO-2024-3221

  * GO-2024-3222

  * GO-2024-3223

  * GO-2024-3224

  * Update to version 0.0.20241017T153730 date 2024-10-17T15:37:30Z. Go CVE
      Numbering Authority IDs added or updated:

  * GO-2024-3189

  * GO-2024-3203

  * GO-2024-3204");

  script_tag(name:"affected", value:"'govulncheck' package(s) on openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
