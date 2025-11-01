# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844687");
  script_cve_id("CVE-2019-16729");
  script_tag(name:"creation_date", value:"2020-10-29 04:00:30 +0000 (Thu, 29 Oct 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-27 20:15:00 +0000 (Tue, 27 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4552-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4552-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4552-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pam-python' package(s) announced via the USN-4552-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4552-1 and USN-4552-2 fixed a vulnerability in Pam-python. The update
introduced a regression which prevented PAM modules written in Python from
importing python modules from site-specific directories.

We apologize for the inconvenience.

Original advisory details:

 Malte Kraus discovered that Pam-python mishandled certain environment variables.
 A local attacker could potentially use this vulnerability to execute programs
 as root.");

  script_tag(name:"affected", value:"'pam-python' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
