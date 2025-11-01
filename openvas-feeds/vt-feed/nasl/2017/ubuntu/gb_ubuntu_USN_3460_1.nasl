# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843345");
  script_cve_id("CVE-2017-7087", "CVE-2017-7089", "CVE-2017-7090", "CVE-2017-7091", "CVE-2017-7092", "CVE-2017-7093", "CVE-2017-7095", "CVE-2017-7096", "CVE-2017-7098", "CVE-2017-7100", "CVE-2017-7102", "CVE-2017-7104", "CVE-2017-7107", "CVE-2017-7109", "CVE-2017-7111", "CVE-2017-7117", "CVE-2017-7120");
  script_tag(name:"creation_date", value:"2017-10-25 13:05:04 +0000 (Wed, 25 Oct 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 16:06:00 +0000 (Fri, 08 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3460-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3460-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3460-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk' package(s) announced via the USN-3460-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A large number of security issues were discovered in the WebKitGTK+ Web and
JavaScript engines. If a user were tricked into viewing a malicious
website, a remote attacker could exploit a variety of issues related to web
browser security, including cross-site scripting attacks, denial of service
attacks, and arbitrary code execution.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Ubuntu 16.04, Ubuntu 17.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
