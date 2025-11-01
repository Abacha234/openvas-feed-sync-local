# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844592");
  script_cve_id("CVE-2018-7738");
  script_tag(name:"creation_date", value:"2020-09-18 03:00:25 +0000 (Fri, 18 Sep 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-25 18:15:00 +0000 (Fri, 25 Sep 2020)");

  script_name("Ubuntu: Security Advisory (USN-4512-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4512-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4512-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the USN-4512-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the umount bash completion script shipped in
util-linux incorrectly handled certain mountpoints. If a local attacker
were able to create arbitrary mountpoints, another user could be tricked
into executing arbitrary code when attempting to run the umount command
with bash completion.");

  script_tag(name:"affected", value:"'util-linux' package(s) on Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
