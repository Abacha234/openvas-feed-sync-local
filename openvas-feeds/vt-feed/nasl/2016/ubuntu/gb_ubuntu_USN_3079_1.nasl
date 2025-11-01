# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842883");
  script_cve_id("CVE-2016-1854", "CVE-2016-1856", "CVE-2016-1857", "CVE-2016-1858", "CVE-2016-1859", "CVE-2016-4583", "CVE-2016-4585", "CVE-2016-4586", "CVE-2016-4588", "CVE-2016-4589", "CVE-2016-4590", "CVE-2016-4591", "CVE-2016-4622", "CVE-2016-4623", "CVE-2016-4624", "CVE-2016-4651");
  script_tag(name:"creation_date", value:"2016-09-15 03:46:35 +0000 (Thu, 15 Sep 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-25 17:04:00 +0000 (Mon, 25 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3079-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3079-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3079-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk' package(s) announced via the USN-3079-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKitGTK+ Web and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of service
attacks, and arbitrary code execution.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
