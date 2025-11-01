# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.841969");
  script_cve_id("CVE-2014-0487", "CVE-2014-0488", "CVE-2014-0489", "CVE-2014-0490");
  script_tag(name:"creation_date", value:"2014-09-17 03:58:42 +0000 (Wed, 17 Sep 2014)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Ubuntu: Security Advisory (USN-2348-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-2348-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2348-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt' package(s) announced via the USN-2348-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that APT did not re-verify downloaded files when the
If-Modified-Since wasn't met. (CVE-2014-0487)

It was discovered that APT did not invalidate repository data when it
switched from an unauthenticated to an authenticated state. (CVE-2014-0488)

It was discovered that the APT Acquire::GzipIndexes option caused APT to
skip checksum validation. This issue only applied to Ubuntu 12.04 LTS and
Ubuntu 14.04 LTS, and was not enabled by default. (CVE-2014-0489)

It was discovered that APT did not correctly validate signatures when
manually downloading packages using the download command. This issue only
applied to Ubuntu 12.04 LTS. (CVE-2014-0490)");

  script_tag(name:"affected", value:"'apt' package(s) on Ubuntu 10.04, Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
