# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885179");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2022-48065", "CVE-2022-48064");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-26 02:15:00 +0000 (Sat, 26 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:21 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for gdb (FEDORA-2023-89ade611ee)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-89ade611ee");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KGSKF4GH7425S6XFDQMWTJGD5U47BAZN");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb'
  package(s) announced via the FEDORA-2023-89ade611ee advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GDB, the GNU debugger, allows you to debug programs written in C, C++,
Fortran, Go, and other languages, by executing them in a controlled
fashion and printing their data.

If you want to use GDB for development purposes, you should install
the &#39, gdb&#39, package which will install &#39, gdb-headless&#39, and possibly other
useful packages too.");

  script_tag(name:"affected", value:"'gdb' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
