# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856700");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2024-50624");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"creation_date", value:"2024-11-08 05:00:38 +0000 (Fri, 08 Nov 2024)");
  script_name("openSUSE: Security Advisory for kmail (openSUSE-SU-2024:0353-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0353-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/RTPM7QBPNV2IRHCZU54SHNI4ODHT6PO4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kmail'
  package(s) announced via the openSUSE-SU-2024:0353-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for kmail-account-wizard fixes the following issues:

  - CVE-2024-50624: Fixed that plaintext HTTP was used for URLs when
       retrieving configuration files (boo#1232454, kde#487882)");

  script_tag(name:"affected", value:"'kmail' package(s) on openSUSE Backports SLE-15-SP5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
