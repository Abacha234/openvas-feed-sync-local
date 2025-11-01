# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856297");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-37370", "CVE-2024-37371");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-27 17:47:30 +0000 (Tue, 27 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 04:01:00 +0000 (Wed, 10 Jul 2024)");
  script_name("openSUSE: Security Advisory for krb5 (SUSE-SU-2024:2322-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2322-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2CZQZSQJ2SGQV6MOELWUKW5ILTITLAEP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'krb5'
  package(s) announced via the SUSE-SU-2024:2322-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for krb5 fixes the following issues:

  * CVE-2024-37370: Fixed confidential GSS krb5 wrap tokens with invalid fields
      were errouneously accepted (bsc#1227186).

  * CVE-2024-37371: Fixed invalid memory read when processing message tokens
      with invalid length fields (bsc#1227187).

  ##");

  script_tag(name:"affected", value:"'krb5' package(s) on openSUSE Leap 15.4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
