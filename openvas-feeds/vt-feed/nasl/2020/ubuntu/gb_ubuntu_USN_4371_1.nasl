# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844444");
  script_cve_id("CVE-2020-10703", "CVE-2020-12430");
  script_tag(name:"creation_date", value:"2020-05-22 03:00:26 +0000 (Fri, 22 May 2020)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-16 03:15:00 +0000 (Tue, 16 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-4371-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4371-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4371-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-4371-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that libvirt incorrectly handled an active pool without a
target path. A remote attacker could possibly use this issue to cause
libvirt to crash, resulting in a denial of service. (CVE-2020-10703)

It was discovered that libvirt incorrectly handled memory when retrieving
certain domain statistics. A remote attacker could possibly use this issue
to cause libvirt to consume resources, resulting in a denial of service.
This issue only affected Ubuntu 19.10. (CVE-2020-12430)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 18.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
