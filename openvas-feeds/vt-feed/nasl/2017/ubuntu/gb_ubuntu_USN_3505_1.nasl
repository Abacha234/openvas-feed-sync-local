# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843392");
  script_cve_id("CVE-2017-13080", "CVE-2017-13081");
  script_tag(name:"creation_date", value:"2017-12-07 06:41:02 +0000 (Thu, 07 Dec 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"2.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3505-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3505-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3505-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-firmware' package(s) announced via the USN-3505-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mathy Vanhoef discovered that the firmware for several Intel WLAN
devices incorrectly handled WPA2 in relation to Wake on WLAN. A
remote attacker could use this issue with key reinstallation attacks
to obtain sensitive information. (CVE-2017-13080, CVE-2017-13081)");

  script_tag(name:"affected", value:"'linux-firmware' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
