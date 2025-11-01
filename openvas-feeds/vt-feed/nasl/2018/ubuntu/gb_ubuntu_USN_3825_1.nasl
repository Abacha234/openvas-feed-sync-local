# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843828");
  script_cve_id("CVE-2011-2767");
  script_tag(name:"creation_date", value:"2018-11-26 14:08:02 +0000 (Mon, 26 Nov 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-09-24 18:15:00 +0000 (Tue, 24 Sep 2019)");

  script_name("Ubuntu: Security Advisory (USN-3825-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3825-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3825-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libapache2-mod-perl2' package(s) announced via the USN-3825-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Ingvoldstad discovered that mod_perl incorrectly handled configuration
options to disable being used by unprivileged users, contrary to the
documentation. A local attacker could possibly use this issue to execute
arbitrary Perl code.");

  script_tag(name:"affected", value:"'libapache2-mod-perl2' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 18.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
