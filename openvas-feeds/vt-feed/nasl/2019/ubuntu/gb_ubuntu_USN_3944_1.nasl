# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843973");
  script_cve_id("CVE-2016-10743", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_tag(name:"creation_date", value:"2019-04-11 02:00:21 +0000 (Thu, 11 Apr 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-22 17:15:00 +0000 (Thu, 22 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-3944-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3944-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3944-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wpa' package(s) announced via the USN-3944-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that wpa_supplicant and hostapd were vulnerable to a
side channel attack against EAP-pwd. A remote attacker could possibly use
this issue to recover certain passwords. (CVE-2019-9495)

Mathy Vanhoef discovered that wpa_supplicant and hostapd incorrectly
validated received scalar and element values in EAP-pwd-Commit messages. A
remote attacker could possibly use this issue to perform a reflection
attack and authenticate without the appropriate password. (CVE-2019-9497,
CVE-2019-9498, CVE-2019-9499)

It was discovered that hostapd incorrectly handled obtaining random
numbers. In rare cases where the urandom device isn't available, it would
fall back to using a low-quality PRNG. This issue only affected Ubuntu
14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-10743)");

  script_tag(name:"affected", value:"'wpa' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
