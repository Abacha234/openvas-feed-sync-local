# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844746");
  script_cve_id("CVE-2020-27348");
  script_tag(name:"creation_date", value:"2020-12-04 04:00:24 +0000 (Fri, 04 Dec 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 20:36:00 +0000 (Mon, 14 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4661-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4661-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4661-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1901572");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snapcraft' package(s) announced via the USN-4661-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Snapcraft includes the current directory when
configuring LD_LIBRARY_PATH for application commands. If a user were
tricked into installing a malicious snap or downloading a malicious
library, under certain circumstances an attacker could exploit this to
affect strict mode snaps that have access to the library and when
launched from the directory containing the library.");

  script_tag(name:"affected", value:"'snapcraft' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
