# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703696");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-8956", "CVE-2016-5195", "CVE-2016-7042", "CVE-2016-7425");
  script_tag(name:"creation_date", value:"2016-10-18 22:00:00 +0000 (Tue, 18 Oct 2016)");
  script_version("2024-01-19T05:06:17+0000");
  script_tag(name:"last_modification", value:"2024-01-19 05:06:17 +0000 (Fri, 19 Jan 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:15:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Debian: Security Advisory (DSA-3696)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");

  script_xref(name:"Advisory-ID", value:"DSA-3696");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3696");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DSA-3696 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2015-8956

It was discovered that missing input sanitising in RFCOMM Bluetooth socket handling may result in denial of service or information leak.

CVE-2016-5195

It was discovered that a race condition in the memory management code can be used for local privilege escalation.

CVE-2016-7042

Ondrej Kozina discovered that incorrect buffer allocation in the proc_keys_show() function may result in local denial of service.

CVE-2016-7425

Marco Grassi discovered a buffer overflow in the arcmsr SCSI driver which may result in local denial of service, or potentially, arbitrary code execution.

Additionally this update fixes a regression introduced in DSA-3616-1 causing iptables performance issues (cf. Debian Bug #831014).

For the stable distribution (jessie), these problems have been fixed in version 3.16.36-1+deb8u2.

We recommend that you upgrade your linux packages.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 8.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);