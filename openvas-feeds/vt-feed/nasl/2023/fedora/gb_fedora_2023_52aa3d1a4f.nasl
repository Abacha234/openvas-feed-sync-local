# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884893");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-4504");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 20:58:00 +0000 (Thu, 09 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-10-01 01:18:19 +0000 (Sun, 01 Oct 2023)");
  script_name("Fedora: Security Advisory for libppd (FEDORA-2023-52aa3d1a4f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-52aa3d1a4f");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T2GSPQAFK2Z6L57TRXEKZDF42K2EVBH7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libppd'
  package(s) announced via the FEDORA-2023-52aa3d1a4f advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Libppd provides all PPD related function/API which is going
to be removed from CUPS 3.X, but are still required for retro-fitting
support of legacy printers. The library is meant only for retro-fitting
printer applications, any new printer drivers have to be written as
native printer application without libppd.");

  script_tag(name:"affected", value:"'libppd' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
