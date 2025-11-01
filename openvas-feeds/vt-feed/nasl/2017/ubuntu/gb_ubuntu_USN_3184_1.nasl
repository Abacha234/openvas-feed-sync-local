# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843030");
  script_cve_id("CVE-2016-7553", "CVE-2017-5193", "CVE-2017-5194", "CVE-2017-5195", "CVE-2017-5196", "CVE-2017-5356");
  script_tag(name:"creation_date", value:"2017-02-03 06:41:07 +0000 (Fri, 03 Feb 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-15 19:32:00 +0000 (Fri, 15 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3184-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3184-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3184-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irssi' package(s) announced via the USN-3184-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Irssi buf.pl script set incorrect permissions. A
local attacker could use this issue to retrieve another user's window
contents. (CVE-2016-7553)

Joseph Bisch discovered that Irssi incorrectly handled comparing nicks. A
remote attacker could use this issue to cause Irssi to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2017-5193)

It was discovered that Irssi incorrectly handled invalid nick messages. A
remote attacker could use this issue to cause Irssi to crash, resulting in
a denial of service, or possibly execute arbitrary code. (CVE-2017-5194)

Joseph Bisch discovered that Irssi incorrectly handled certain incomplete
control codes. A remote attacker could use this issue to cause Irssi to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 16.04 LTS and Ubuntu 16.10.
(CVE-2017-5195)

Hanno Bock and Joseph Bisch discovered that Irssi incorrectly handled
certain incomplete character sequences. A remote attacker could use this
issue to cause Irssi to crash, resulting in a denial of service. This issue
only affected Ubuntu 16.04 LTS and Ubuntu 16.10. (CVE-2017-5196)

Hanno Bock discovered that Irssi incorrectly handled certain format
strings. A remote attacker could use this issue to cause Irssi to crash,
resulting in a denial of service. (CVE-2017-5356)");

  script_tag(name:"affected", value:"'irssi' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
