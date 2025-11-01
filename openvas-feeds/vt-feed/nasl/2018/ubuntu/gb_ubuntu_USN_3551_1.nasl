# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843437");
  script_cve_id("CVE-2017-13884", "CVE-2017-13885", "CVE-2017-7153", "CVE-2017-7160", "CVE-2017-7161", "CVE-2017-7165", "CVE-2018-4088", "CVE-2018-4096");
  script_tag(name:"creation_date", value:"2018-01-31 06:54:47 +0000 (Wed, 31 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-04-27 17:48:00 +0000 (Fri, 27 Apr 2018)");

  script_name("Ubuntu: Security Advisory (USN-3551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3551-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3551-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk' package(s) announced via the USN-3551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in the WebKitGTK+ Web and
JavaScript engines. If a user were tricked in to opening a specially
crafted website, an attacker could potentially exploit these to cause a
denial of service, spoof the user interface, or execute arbitrary code.
(CVE-2018-4088, CVE-2018-4096, CVE-2017-7153, CVE-2017-7160,
CVE-2017-7161, CVE-2017-7165, CVE-2017-13884, CVE-2017-13885)");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
