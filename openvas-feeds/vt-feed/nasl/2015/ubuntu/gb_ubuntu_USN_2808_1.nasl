# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842531");
  script_cve_id("CVE-2015-5310", "CVE-2015-5314", "CVE-2015-5315", "CVE-2015-5316");
  script_tag(name:"creation_date", value:"2015-11-11 05:06:51 +0000 (Wed, 11 Nov 2015)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-21 13:06:00 +0000 (Wed, 21 Mar 2018)");

  script_name("Ubuntu: Security Advisory (USN-2808-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2808-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2808-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa' package(s) announced via the USN-2808-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wpa_supplicant incorrectly handled WMM Sleep Mode
Response frame processing. A remote attacker could use this issue to
perform broadcast/multicast packet injections, or cause a denial of
service. (CVE-2015-5310)

It was discovered that wpa_supplicant and hostapd incorrectly handled
certain EAP-pwd messages. A remote attacker could use this issue to cause a
denial of service. (CVE-2015-5314, CVE-2015-5315)

It was discovered that wpa_supplicant incorrectly handled certain EAP-pwd
Confirm messages. A remote attacker could use this issue to cause a
denial of service. This issue only applied to Ubuntu 15.10. (CVE-2015-5316)");

  script_tag(name:"affected", value:"'wpa' package(s) on Ubuntu 14.04, Ubuntu 15.04, Ubuntu 15.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
