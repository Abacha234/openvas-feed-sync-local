# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856927");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2023-41081", "CVE-2024-46544");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-15 13:26:15 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2025-01-15 05:01:35 +0000 (Wed, 15 Jan 2025)");
  script_name("openSUSE: Security Advisory for apache2 (SUSE-SU-2025:0102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0102-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/HDFX72CFMICS52ZQIPSJGCJBCNOILALD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2'
  package(s) announced via the SUSE-SU-2025:0102-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for apache2-mod_jk fixes the following issues:

  * Update to version 1.2.50:

  * CVE-2024-46544: Fixed incorrect default permissions vulnerabilitymay that
      could lead to information disclosure and/or denial of service. (bsc#1230916)

  * CVE-2023-41081: Fixed information disclosure in mod_jk. (bsc#1215301)");

  script_tag(name:"affected", value:"'apache2' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
