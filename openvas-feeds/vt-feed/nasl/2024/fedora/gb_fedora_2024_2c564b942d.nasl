# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886677");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-3550", "CVE-2023-45360", "CVE-2023-45362", "CVE-2023-51704", "CVE-2024-34507", "CVE-2024-34506", "CVE-2024-34500", "CVE-2024-34502");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-25 16:15:14 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"creation_date", value:"2024-05-27 10:44:50 +0000 (Mon, 27 May 2024)");
  script_name("Fedora: Security Advisory for php-wikimedia-cdb (FEDORA-2024-2c564b942d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2c564b942d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5XX6JO3YEUMC63PRDVIFZ63H7INPRCPL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-wikimedia-cdb'
  package(s) announced via the FEDORA-2024-2c564b942d advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CDB, short for 'constant database', refers to a very fast and highly reliable
database system which uses a simple file with key value pairs. This library
wraps the CDB functionality exposed in PHP via the dba_* functions. In cases
where dba_* functions are not present or are not compiled with CDB support,
a pure-PHP implementation is provided for falling back.");

  script_tag(name:"affected", value:"'php-wikimedia-cdb' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
