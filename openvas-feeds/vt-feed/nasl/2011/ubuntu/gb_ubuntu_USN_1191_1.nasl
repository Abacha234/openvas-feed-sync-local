# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840721");
  script_cve_id("CVE-2011-2895");
  script_tag(name:"creation_date", value:"2011-08-18 12:57:45 +0000 (Thu, 18 Aug 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1191-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1191-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1191-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxfont' package(s) announced via the USN-1191-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tomas Hoger discovered that libXfont incorrectly handled certain malformed
compressed fonts. An attacker could use a specially crafted font file to
cause libXfont to crash, or possibly execute arbitrary code in order to
gain privileges.");

  script_tag(name:"affected", value:"'libxfont' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
