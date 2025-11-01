# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856293");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-24814");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-10-21 20:02:16 +0000 (Mon, 21 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-07-10 04:00:55 +0000 (Wed, 10 Jul 2024)");
  script_name("openSUSE: Security Advisory for apache2 (SUSE-SU-2024:2299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2299-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZXPO7H4K5ILKFETTAWJUML6P6C3KYRWO");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the SUSE-SU-2024:2299-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_auth_openidc fixes the following issues:

  * CVE-2024-24814: Fixed a bug that can led to DoS when `OIDCSessionType
      client-cookie` is set and a crafted Cookie header is supplied. (bsc#1219911)

  ##");

  script_tag(name:"affected", value:"'apache2' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
