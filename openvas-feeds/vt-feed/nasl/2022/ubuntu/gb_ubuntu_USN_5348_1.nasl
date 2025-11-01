# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845297");
  script_cve_id("CVE-2018-13982", "CVE-2018-16831", "CVE-2021-21408", "CVE-2021-26119", "CVE-2021-26120", "CVE-2021-29454");
  script_tag(name:"creation_date", value:"2022-03-29 01:00:49 +0000 (Tue, 29 Mar 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 10:15:00 +0000 (Wed, 26 May 2021)");

  script_name("Ubuntu: Security Advisory (USN-5348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5348-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5348-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'smarty3' package(s) announced via the USN-5348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Gnedt and Thomas Konrad discovered that Smarty was incorrectly
sanitizing the paths present in the templates. An attacker could possibly
use this use to read arbitrary files when controlling the executed
template. (CVE-2018-13982)

It was discovered that Smarty was incorrectly sanitizing the paths
present in the templates. An attacker could possibly use this use to read
arbitrary files when controlling the executed template. (CVE-2018-16831)

It was discovered that Smarty was incorrectly validating security policy
data, allowing the execution of static classes even when not permitted by
the security settings. An attacker could possibly use this issue to
execute arbitrary code. (CVE-2021-21408)

It was discovered that Smarty was incorrectly managing access control to
template objects, which allowed users to perform a sandbox escape. An
attacker could possibly use this issue to send specially crafted input to
applications that use Smarty and execute arbitrary code. (CVE-2021-26119)

It was discovered that Smarty was not checking for special characters
when setting function names during plugin compile operations. An attacker
could possibly use this issue to send specially crafted input to
applications that use Smarty and execute arbitrary code. (CVE-2021-26120)

It was discovered that Smarty was incorrectly sanitizing characters in
math strings processed by the math function. An attacker could possibly
use this issue to send specially crafted input to applications that use
Smarty and execute arbitrary code. (CVE-2021-29454)");

  script_tag(name:"affected", value:"'smarty3' package(s) on Ubuntu 18.04, Ubuntu 21.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
