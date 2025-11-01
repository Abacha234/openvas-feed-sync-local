# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842176");
  script_cve_id("CVE-2015-1863");
  script_tag(name:"creation_date", value:"2015-04-24 04:06:27 +0000 (Fri, 24 Apr 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2577-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2577-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2577-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa' package(s) announced via the USN-2577-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wpa_supplicant incorrectly handled SSID information
when creating or updating P2P peer entries. A remote attacker could use
this issue to cause wpa_supplicant to crash, resulting in a denial of
service, expose memory contents, or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"'wpa' package(s) on Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
