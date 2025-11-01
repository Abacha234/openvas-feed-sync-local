# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844263");
  script_cve_id("CVE-2019-11135", "CVE-2019-11139");
  script_tag(name:"creation_date", value:"2019-12-05 03:00:47 +0000 (Thu, 05 Dec 2019)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-4182-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Ubuntu Local Security Checks");

  script_xref(name:"Advisory-ID", value:"USN-4182-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4182-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1854764");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode' package(s) announced via the USN-4182-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4182-1 provided updated Intel Processor Microcode. A regression
was discovered that caused some Skylake processors to hang after
a warm reboot. This update reverts the microcode for that specific
processor family.

We apologize for the inconvenience.

Original advisory details:

 Stephan van Schaik, Alyssa Milburn, Sebastian Osterlund, Pietro Frigo,
 Kaveh Razavi, Herbert Bos, Cristiano Giuffrida, Giorgi Maisuradze, Moritz
 Lipp, Michael Schwarz, Daniel Gruss, and Jo Van Bulck discovered that Intel
 processors using Transactional Synchronization Extensions (TSX) could
 expose memory contents previously stored in microarchitectural buffers to a
 malicious process that is executing on the same CPU core. A local attacker
 could use this to expose sensitive information. (CVE-2019-11135)

 It was discovered that certain Intel Xeon processors did not properly
 restrict access to a voltage modulation interface. A local privileged
 attacker could use this to cause a denial of service (system crash).
 (CVE-2019-11139)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04, Ubuntu 19.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
