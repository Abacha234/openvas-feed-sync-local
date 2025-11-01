# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841531");
  script_cve_id("CVE-2013-2142");
  script_tag(name:"creation_date", value:"2013-08-16 03:34:25 +0000 (Fri, 16 Aug 2013)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-1927-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1927-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1927-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libimobiledevice' package(s) announced via the USN-1927-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paul Collins discovered that libimobiledevice incorrectly handled temporary
files. A local attacker could possibly use this issue to overwrite
arbitrary files and access device keys. In the default Ubuntu installation,
this issue should be mitigated by the Yama link restrictions.");

  script_tag(name:"affected", value:"'libimobiledevice' package(s) on Ubuntu 12.10, Ubuntu 13.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
