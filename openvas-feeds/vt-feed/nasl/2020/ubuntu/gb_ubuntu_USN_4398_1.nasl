# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844471");
  script_cve_id("CVE-2020-12049");
  script_tag(name:"creation_date", value:"2020-06-17 03:00:16 +0000 (Wed, 17 Jun 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-04 21:17:00 +0000 (Thu, 04 Mar 2021)");

  script_name("Ubuntu: Security Advisory (USN-4398-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4398-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4398-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dbus' package(s) announced via the USN-4398-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Backhouse discovered that DBus incorrectly handled file descriptors.
A local attacker could possibly use this issue to cause DBus to crash,
resulting in a denial of service.");

  script_tag(name:"affected", value:"'dbus' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
