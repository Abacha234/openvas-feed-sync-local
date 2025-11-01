# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845134");
  script_cve_id("CVE-2017-17087", "CVE-2019-20807", "CVE-2021-3872", "CVE-2021-3903", "CVE-2021-3927", "CVE-2021-3928");
  script_tag(name:"creation_date", value:"2021-11-16 02:00:30 +0000 (Tue, 16 Nov 2021)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-10 05:15:00 +0000 (Wed, 10 Nov 2021)");

  script_name("Ubuntu: Security Advisory (USN-5147-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5147-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5147-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-5147-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim incorrectly handled permissions on the .swp
file. A local attacker could possibly use this issue to obtain sensitive
information. This issue only affected Ubuntu 14.04 ESM. (CVE-2017-17087)

It was discovered that Vim incorrectly handled restricted mode. A local
attacker could possibly use this issue to bypass restricted mode and
execute arbitrary commands. Note: This update only makes executing shell
commands more difficult. Restricted mode should not be considered a
complete security measure. This issue only affected Ubuntu 14.04 ESM.
(CVE-2019-20807)

Brian Carpenter discovered that vim incorrectly handled memory
when opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. This issue only affected
Ubuntu 20.04 LTS, Ubuntu 21.04 and Ubuntu 21.10. (CVE-2021-3872)

It was discovered that vim incorrectly handled memory when
opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. (CVE-2021-3903)

It was discovered that vim incorrectly handled memory when
opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. (CVE-2021-3927)

It was discovered that vim incorrectly handled memory when
opening certain files. If a user was tricked into opening
a specially crafted file, a remote attacker could crash the
application, leading to a denial of service, or possible execute
arbitrary code with user privileges. (CVE-2021-3928)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
