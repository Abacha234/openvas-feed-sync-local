# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63071");
  script_cve_id("CVE-2008-1102", "CVE-2008-4863");
  script_tag(name:"creation_date", value:"2008-12-29 21:42:24 +0000 (Mon, 29 Dec 2008)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-699-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-699-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'blender' package(s) announced via the USN-699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Blender did not correctly handle certain malformed
Radiance RGBE images. If a user were tricked into opening a .blend file
containing a specially crafted Radiance RGBE image, an attacker could execute
arbitrary code with the user's privileges. (CVE-2008-1102)

It was discovered that Blender did not properly sanitize the Python search
path. A local attacker could execute arbitrary code by inserting a specially
crafted Python file in the Blender working directory. (CVE-2008-4863)");

  script_tag(name:"affected", value:"'blender' package(s) on Ubuntu 6.06.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
