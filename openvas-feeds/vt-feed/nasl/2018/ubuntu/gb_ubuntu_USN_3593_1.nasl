# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843682");
  script_cve_id("CVE-2014-10070", "CVE-2014-10071", "CVE-2014-10072", "CVE-2016-10714", "CVE-2017-18205", "CVE-2017-18206", "CVE-2018-7548", "CVE-2018-7549");
  script_tag(name:"creation_date", value:"2018-10-26 04:06:19 +0000 (Fri, 26 Oct 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 18:30:00 +0000 (Tue, 05 Mar 2019)");

  script_name("Ubuntu: Security Advisory (USN-3593-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3593-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3593-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh' package(s) announced via the USN-3593-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Zsh incorrectly handled certain environment variables.
An attacker could possibly use this issue to gain privileged access to the
system. This issue only affected Ubuntu 14.04 LTS. (CVE-2014-10070)

It was discovered that Zsh incorrectly handled certain inputs.
An attacker could possibly use this to execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS. (CVE-2014-10071)

It was discovered that Zsh incorrectly handled some symbolic links.
An attacker could possibly use this to execute arbitrary code. This issue
only affected Ubuntu 14.04 LTS. (CVE-2014-10072)

It was discovered that Zsh incorrectly handled certain errors. An attacker
could possibly use this issue to cause a denial of service. (CVE-2016-10714)

It was discovered that Zsh incorrectly handled certain commands. An attacker
could possibly use this to execute arbitrary code. (CVE-2017-18205)

It was discovered that Zsh incorrectly handled certain symlinks. An attacker
could possibly use this to execute arbitrary code. This issue only affected
Ubuntu 16.04 LTS and Ubuntu 17.10. (CVE-2017-18206)

It was discovered that Zsh incorrectly handled certain inputs. An attacker could
possible use to execute arbitrary code. This issue only affected Ubuntu 17.10.
(CVE-2018-7548)

It was discovered that Zsh incorrectly handled certain inputs. An attacker
could possibly use this to cause a denial of service. (CVE-2018-7549)");

  script_tag(name:"affected", value:"'zsh' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
