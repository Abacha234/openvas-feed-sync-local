# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843451");
  script_cve_id("CVE-2018-5378", "CVE-2018-5379", "CVE-2018-5380", "CVE-2018-5381");
  script_tag(name:"creation_date", value:"2018-02-16 07:25:08 +0000 (Fri, 16 Feb 2018)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:41:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-3573-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3573-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'quagga' package(s) announced via the USN-3573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that a double-free vulnerability existed in the
Quagga BGP daemon when processing certain forms of UPDATE message.
A remote attacker could use this to cause a denial of service or
possibly execute arbitrary code. (CVE-2018-5379)

It was discovered that the Quagga BGP daemon did not properly bounds
check the data sent with a NOTIFY to a peer. An attacker could use this
to expose sensitive information or possibly cause a denial of service.
This issue only affected Ubuntu 17.10. (CVE-2018-5378)

It was discovered that a table overrun vulnerability existed in the
Quagga BGP daemon. An attacker in control of a configured peer could
use this to possibly expose sensitive information or possibly cause
a denial of service. (CVE-2018-5380)

It was discovered that the Quagga BGP daemon in some configurations
did not properly handle invalid OPEN messages. An attacker in control
of a configured peer could use this to cause a denial of service
(infinite loop). (CVE-2018-5381)");

  script_tag(name:"affected", value:"'quagga' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 17.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
