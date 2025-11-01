# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840828");
  script_cve_id("CVE-2011-2491", "CVE-2011-2496", "CVE-2011-2517", "CVE-2011-2525");
  script_tag(name:"creation_date", value:"2011-12-05 07:09:55 +0000 (Mon, 05 Dec 2011)");
  script_version("2024-01-19T05:06:16+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:16 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-04 15:13:00 +0000 (Tue, 04 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-1286-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-1286-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1286-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux' package(s) announced via the USN-1286-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vasily Averin discovered that the NFS Lock Manager (NLM) incorrectly
handled unlock requests. A local attacker could exploit this to cause a
denial of service. (CVE-2011-2491)

Robert Swiecki discovered that mapping extensions were incorrectly handled.
A local attacker could exploit this to crash the system, leading to a
denial of service. (CVE-2011-2496)

It was discovered that the wireless stack incorrectly verified SSID
lengths. A local attacker could exploit this to cause a denial of service
or gain root privileges. (CVE-2011-2517)

Ben Pfaff discovered that Classless Queuing Disciplines (qdiscs) were being
incorrectly handled. A local attacker could exploit this to crash the
system, leading to a denial of service. (CVE-2011-2525)");

  script_tag(name:"affected", value:"'linux' package(s) on Ubuntu 10.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
