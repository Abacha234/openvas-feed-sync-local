# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843087");
  script_cve_id("CVE-2016-5418", "CVE-2016-6250", "CVE-2016-7166", "CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689", "CVE-2017-5601");
  script_tag(name:"creation_date", value:"2017-03-10 04:53:47 +0000 (Fri, 10 Mar 2017)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");

  script_name("Ubuntu: Security Advisory (USN-3225-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3225-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3225-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive' package(s) announced via the USN-3225-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libarchive incorrectly handled hardlink entries when
extracting archives. A remote attacker could possibly use this issue to
overwrite arbitrary files. (CVE-2016-5418)

Christian Wressnegger, Alwin Maier, and Fabian Yamaguchi discovered that
libarchive incorrectly handled filename lengths when writing ISO9660
archives. A remote attacker could use this issue to cause libarchive to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and
Ubuntu 16.04 LTS. (CVE-2016-6250)

Alexander Cherepanov discovered that libarchive incorrectly handled
recursive decompressions. A remote attacker could possibly use this issue
to cause libarchive to hang, resulting in a denial of service. This issue
only applied to Ubuntu 12.04 LTS, Ubuntu 14.04 LTS and Ubuntu 16.04 LTS.
(CVE-2016-7166)

It was discovered that libarchive incorrectly handled non-printable
multibyte characters in filenames. A remote attacker could possibly use
this issue to cause libarchive to crash, resulting in a denial of service.
(CVE-2016-8687)

It was discovered that libarchive incorrectly handled line sizes when
extracting certain archives. A remote attacker could possibly use this
issue to cause libarchive to crash, resulting in a denial of service.
(CVE-2016-8688)

It was discovered that libarchive incorrectly handled multiple EmptyStream
attributes when extracting certain 7zip archives. A remote attacker could
possibly use this issue to cause libarchive to crash, resulting in a denial
of service. (CVE-2016-8689)

Jakub Jirasek discovered that libarchive incorrectly handled memory when
extracting certain archives. A remote attacker could possibly use this
issue to cause libarchive to crash, resulting in a denial of service.
(CVE-2017-5601)");

  script_tag(name:"affected", value:"'libarchive' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 16.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
