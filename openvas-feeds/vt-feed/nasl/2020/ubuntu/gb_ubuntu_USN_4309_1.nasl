# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844372");
  script_cve_id("CVE-2017-11109", "CVE-2017-5953", "CVE-2017-6349", "CVE-2017-6350", "CVE-2018-20786", "CVE-2019-20079");
  script_tag(name:"creation_date", value:"2020-03-24 04:00:36 +0000 (Tue, 24 Mar 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-13 21:47:00 +0000 (Mon, 13 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-4309-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4309-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4309-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-4309-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim incorrectly handled certain sources.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and
Ubuntu 16.04 LTS (CVE-2017-11109)

It was discovered that Vim incorrectly handled certain files.
An attacker could possibly use this issue to execute arbitrary code.
This issue only affected Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.
(CVE-2017-5953)

It was discovered that Vim incorrectly handled certain inputs.
An attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 16.06 LTS. (CVE-2018-20786)

It was discovered that Vim incorrectly handled certain inputs. An attacker
could possibly use this issue to cause a denial of service or
execute arbitrary code. This issue only affected Ubuntu 18.04 LTS and
Ubuntu 19.10. (CVE-2019-20079)

It was discovered that Vim incorrectly handled certain files. An attacker
could possibly use this issue to execute arbitrary code. This issue
only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04 LTS.
(CVE-2017-6349, CVE-2017-6350)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
