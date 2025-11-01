# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845367");
  script_cve_id("CVE-2022-1158", "CVE-2022-1516", "CVE-2022-28388", "CVE-2022-28389", "CVE-2022-28390");
  script_tag(name:"creation_date", value:"2022-05-13 01:00:44 +0000 (Fri, 13 May 2022)");
  script_version("2024-01-19T05:06:18+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:18 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 18:28:00 +0000 (Fri, 13 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-5416-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-5416-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5416-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta-oem-5.14, linux-oem-5.14, linux-signed-oem-5.14' package(s) announced via the USN-5416-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qiuhao Li, Gaoning Pan and Yongkang Jia discovered that the KVM
implementation in the Linux kernel did not properly perform guest page
table updates in some situations. An attacker in a guest vm could possibly
use this to crash the host OS. (CVE-2022-1158)

It was discovered that the implementation of X.25 network protocols in the
Linux kernel did not terminate link layer sessions properly. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-1516)

It was discovered that the 8 Devices USB2CAN interface implementation in
the Linux kernel did not properly handle certain error conditions, leading
to a double-free. A local attacker could possibly use this to cause a
denial of service (system crash). (CVE-2022-28388)

It was discovered that the Microchip CAN BUS Analyzer interface
implementation in the Linux kernel did not properly handle certain error
conditions, leading to a double-free. A local attacker could possibly use
this to cause a denial of service (system crash). (CVE-2022-28389)

It was discovered that the EMS CAN/USB interface implementation in the
Linux kernel contained a double-free vulnerability when handling certain
error conditions. A local attacker could use this to cause a denial of
service (memory exhaustion). (CVE-2022-28390)");

  script_tag(name:"affected", value:"'linux-meta-oem-5.14, linux-oem-5.14, linux-signed-oem-5.14' package(s) on Ubuntu 20.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
