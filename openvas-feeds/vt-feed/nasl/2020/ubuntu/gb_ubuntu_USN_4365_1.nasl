# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844440");
  script_cve_id("CVE-2020-8616", "CVE-2020-8617");
  script_tag(name:"creation_date", value:"2020-05-20 03:00:33 +0000 (Wed, 20 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)");

  script_name("Ubuntu: Security Advisory (USN-4365-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4365-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4365-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind9' package(s) announced via the USN-4365-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Lior Shafir, Yehuda Afek, and Anat Bremler-Barr discovered that Bind
incorrectly limited certain fetches. A remote attacker could possibly use
this issue to cause Bind to consume resources, leading to a denial of
service, or possibly use Bind to perform a reflection attack.
(CVE-2020-8616)

Tobias Klein discovered that Bind incorrectly handled checking TSIG
validity. A remote attacker could use this issue to cause Bind to crash,
resulting in a denial of service, or possibly perform other attacks.
(CVE-2020-8617)");

  script_tag(name:"affected", value:"'bind9' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.10, Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
