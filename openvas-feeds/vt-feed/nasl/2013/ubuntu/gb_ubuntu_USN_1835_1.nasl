# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841434");
  script_cve_id("CVE-2013-1929", "CVE-2013-3301");
  script_tag(name:"creation_date", value:"2013-05-27 06:24:38 +0000 (Mon, 27 May 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1835-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1835-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1835-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1835-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow vulnerability was discovered in the Broadcom tg3 ethernet
driver for the Linux kernel. A local user could exploit this flaw to cause
a denial of service (crash the system) or potentially escalate privileges
on the system. (CVE-2013-1929)

A flaw was discovered in the Linux kernel's ftrace subsystem interface. A
local user could exploit this flaw to cause a denial of service (system
crash). (CVE-2013-3301)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 12.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
