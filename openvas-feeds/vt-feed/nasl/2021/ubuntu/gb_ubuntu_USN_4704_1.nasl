# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844799");
  script_cve_id("CVE-2017-12562", "CVE-2017-14245", "CVE-2017-14246", "CVE-2017-14634", "CVE-2017-16942", "CVE-2017-6892", "CVE-2018-13139", "CVE-2018-19432", "CVE-2018-19661", "CVE-2018-19662", "CVE-2018-19758", "CVE-2019-3832");
  script_tag(name:"creation_date", value:"2021-01-27 04:00:22 +0000 (Wed, 27 Jan 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-03 11:29:00 +0000 (Mon, 03 Dec 2018)");

  script_name("Ubuntu: Security Advisory (USN-4704-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4704-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4704-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsndfile' package(s) announced via the USN-4704-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libsndfile incorrectly handled certain malformed
files. A remote attacker could use this issue to cause libsndfile to
crash, resulting in a denial of service, or possibly execute arbitrary
code. (CVE-2017-12562)

It was discovered that libsndfile incorrectly handled certain malformed
files. A remote attacker could use this issue to cause libsndfile to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 14.04 ESM. (CVE-2017-14245,
CVE-2017-14246, CVE-2017-14634, CVE-2017-16942, CVE-2017-6892,
CVE-2018-13139, CVE-2018-19432, CVE-2018-19661, CVE-2018-19662,
CVE-2018-19758, CVE-2019-3832)");

  script_tag(name:"affected", value:"'libsndfile' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
