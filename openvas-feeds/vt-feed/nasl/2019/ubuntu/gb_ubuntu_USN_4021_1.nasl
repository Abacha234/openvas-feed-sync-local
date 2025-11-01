# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844057");
  script_cve_id("CVE-2019-10132", "CVE-2019-3886");
  script_tag(name:"creation_date", value:"2019-06-20 02:00:33 +0000 (Thu, 20 Jun 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-11 16:29:00 +0000 (Tue, 11 Jun 2019)");

  script_name("Ubuntu: Security Advisory (USN-4021-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4021-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4021-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libvirt' package(s) announced via the USN-4021-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel P. Berrange discovered that libvirt incorrectly handled socket
permissions. A local attacker could possibly use this issue to access
libvirt. (CVE-2019-10132)

It was discovered that libvirt incorrectly performed certain permission
checks. A remote attacker could possibly use this issue to access the
guest agent and cause a denial of service. This issue only affected Ubuntu
19.04. (CVE-2019-3886)");

  script_tag(name:"affected", value:"'libvirt' package(s) on Ubuntu 18.10, Ubuntu 19.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
