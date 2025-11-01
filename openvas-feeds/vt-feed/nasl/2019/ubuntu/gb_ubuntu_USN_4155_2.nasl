# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844272");
  script_cve_id("CVE-2019-17544");
  script_tag(name:"creation_date", value:"2019-12-12 03:00:54 +0000 (Thu, 12 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-19 21:15:00 +0000 (Sat, 19 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4155-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4155-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4155-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aspell' package(s) announced via the USN-4155-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4155-1 fixed a vulnerability in Aspell. This update provides
the corresponding update for Ubuntu 19.10.

Original advisory details:

 It was discovered that Aspell incorrectly handled certain inputs.
 An attacker could potentially access sensitive information.");

  script_tag(name:"affected", value:"'aspell' package(s) on Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
