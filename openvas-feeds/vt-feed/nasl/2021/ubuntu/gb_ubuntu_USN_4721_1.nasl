# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844817");
  script_cve_id("CVE-2021-21261");
  script_tag(name:"creation_date", value:"2021-02-05 04:00:25 +0000 (Fri, 05 Feb 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-27 19:34:00 +0000 (Wed, 27 Jan 2021)");

  script_name("Ubuntu: Security Advisory (USN-4721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4721-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4721-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'flatpak' package(s) announced via the USN-4721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Simon McVittie discovered that flatpak-portal service allowed sandboxed
applications to execute arbitrary code on the host system (a sandbox
escape). A malicious user could create a Flatpak application that set
environment variables, trusted by the Flatpak 'run' command, and use it
to execute arbitrary code outside the sandbox.");

  script_tag(name:"affected", value:"'flatpak' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 20.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
