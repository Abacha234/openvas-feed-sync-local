# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884793");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2022-45061");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 21:17:00 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"creation_date", value:"2023-09-16 01:15:21 +0000 (Sat, 16 Sep 2023)");
  script_name("Fedora: Security Advisory for pypy (FEDORA-2023-5460cf6dfb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-5460cf6dfb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/B4MYQ3IV6NWA4CKSXEHW45CH2YNDHEPH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pypy'
  package(s) announced via the FEDORA-2023-5460cf6dfb advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"PyPy&#39, s implementation of Python, featuring a Just-In-Time compiler on some CPU
architectures, and various optimized implementations of the standard types
(strings, dictionaries, etc)


This build of PyPy has JIT-compilation enabled.");

  script_tag(name:"affected", value:"'pypy' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
