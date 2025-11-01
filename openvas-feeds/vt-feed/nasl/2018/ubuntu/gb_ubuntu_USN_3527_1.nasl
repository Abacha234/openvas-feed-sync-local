# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843417");
  script_cve_id("CVE-2018-5205", "CVE-2018-5206", "CVE-2018-5207", "CVE-2018-5208");
  script_tag(name:"creation_date", value:"2018-01-11 06:38:51 +0000 (Thu, 11 Jan 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-12 12:20:00 +0000 (Tue, 12 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3527-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3527-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3527-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi' package(s) announced via the USN-3527-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Joseph Bisch discovered that Irssi incorrectly handled incomplete escape
codes. If a user were tricked into using malformed commands or opening
malformed files, an attacker could use this issue to cause Irssi to crash,
resulting in a denial of service. (CVE-2018-5205)

Joseph Bisch discovered that Irssi incorrectly handled settings the channel
topic without specifying a sender. A malicious IRC server could use this
issue to cause Irssi to crash, resulting in a denial of service.
(CVE-2018-5206)

Joseph Bisch discovered that Irssi incorrectly handled incomplete variable
arguments. If a user were tricked into using malformed commands or opening
malformed files, an attacker could use this issue to cause Irssi to crash,
resulting in a denial of service. (CVE-2018-5207)

Joseph Bisch discovered that Irssi incorrectly handled completing certain
strings. An attacker could use this issue to cause Irssi to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2018-5208)");

  script_tag(name:"affected", value:"'irssi' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
